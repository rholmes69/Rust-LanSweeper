//! CSV import: bulk-update asset details (owner, department, serial, warranty, custom fields…)
//! and optionally add devices the scanner can't see.
//!
//! Rows are matched to existing assets by the first identifier column that is present, in order:
//! `id`, `asset_tag`, `serial_number`, `mac`, `ip`, `name`. The file exported from the Assets
//! page can be edited in Excel and imported back. Empty cells leave a field unchanged; a cell
//! containing just `-` clears it. Read-only columns (vendor, device_type, …) are ignored.

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::db::{normalize_field, Asset, AssetFilter, Db, EDITABLE_FIELDS};

#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Create assets for rows that match nothing (needs ip, mac or name).
    pub create_missing: bool,
    /// Report what would change without writing anything.
    pub dry_run: bool,
    /// Recorded as the asset `source` for created rows.
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RowResult {
    /// 1-based data row number (header excluded).
    pub row: usize,
    pub asset_id: Option<i64>,
    pub asset: Option<String>,
    pub action: String,
    pub changes: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ImportReport {
    pub dry_run: bool,
    pub rows: usize,
    pub matched: usize,
    pub created: usize,
    pub updated_assets: usize,
    pub fields_changed: usize,
    pub skipped: usize,
    pub key_columns: Vec<String>,
    pub update_columns: Vec<String>,
    pub ignored_columns: Vec<String>,
    pub results: Vec<RowResult>,
}

#[derive(Debug, Clone, PartialEq)]
enum Col {
    Key(&'static str),
    Field(&'static str),
    Custom(String),
    Site,
    Ignored,
}

const KEYS: &[&str] = &["id", "asset_tag", "serial_number", "mac", "ip", "name"];

fn normalise_header(h: &str) -> String {
    h.trim().trim_start_matches('\u{feff}').to_lowercase().replace([' ', '-'], "_")
}

fn classify(header: &str, custom: &[String]) -> Col {
    let raw = header.trim().trim_start_matches('\u{feff}');
    let h = normalise_header(raw);
    let alias = match h.as_str() {
        "asset_id" => "id",
        "tag" | "assettag" => "asset_tag",
        "serial" | "serial_no" | "serialnumber" | "sn" => "serial_number",
        "mac_address" => "mac",
        "ip_address" | "ipaddress" => "ip",
        "hostname" | "computer_name" | "asset_name" => "name",
        "display_name" | "custom_name" => "name_override",
        "cost_centre" | "costcenter" => "cost_center",
        "po" | "po_no" | "purchase_order" => "po_number",
        "warranty" | "warranty_expiry" | "warranty_expires" | "warranty_end_date" => "warranty_end",
        "purchased" | "purchase" => "purchase_date",
        "user" | "assigned_to" => "owner",
        "dept" => "department",
        "make" => "manufacturer",
        other => other,
    };
    if let Some(k) = KEYS.iter().find(|k| **k == alias) {
        // asset_tag / serial_number are both identifiers and editable; treated as keys first.
        return Col::Key(k);
    }
    if let Some((c, _)) = EDITABLE_FIELDS.iter().find(|(c, l)| *c == alias || normalise_header(l) == alias) {
        return Col::Field(c);
    }
    if alias == "site" {
        return Col::Site;
    }
    let bare = raw.strip_prefix("custom:").unwrap_or(raw).trim();
    if let Some(name) = custom.iter().find(|n| n.eq_ignore_ascii_case(bare)) {
        return Col::Custom(name.clone());
    }
    Col::Ignored
}

/// Find the asset for one row. Ok(None) = no match; Err = ambiguous/invalid.
fn find_asset(assets: &[Asset], key: &str, value: &str) -> Result<Option<i64>> {
    let v = value.trim();
    let hits: Vec<&Asset> = match key {
        "id" => {
            let id: i64 = v.parse().map_err(|_| anyhow::anyhow!("id '{v}' is not a number"))?;
            assets.iter().filter(|a| a.id == id).collect()
        }
        "asset_tag" => assets.iter().filter(|a| a.asset_tag.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(v))).collect(),
        "serial_number" => assets.iter().filter(|a| a.serial_number.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(v))).collect(),
        "mac" => {
            let m = crate::scanner::arp::normalize_mac(v).ok_or_else(|| anyhow::anyhow!("'{v}' is not a MAC address"))?;
            assets.iter().filter(|a| a.mac.as_deref() == Some(m.as_str())).collect()
        }
        "ip" => assets.iter().filter(|a| a.ip == v).collect(),
        "name" => assets.iter().filter(|a| a.display_name().eq_ignore_ascii_case(v) || a.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(v))).collect(),
        _ => vec![],
    };
    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits[0].id)),
        n => bail!("{key} '{v}' matches {n} assets — add an id or asset_tag column to disambiguate"),
    }
}

pub fn import_csv(db: &Db, data: &str, opts: &ImportOptions) -> Result<ImportReport> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).trim(csv::Trim::All).from_reader(data.as_bytes());
    let headers: Vec<String> = rdr.headers()?.iter().map(str::to_string).collect();
    if headers.iter().all(|h| h.trim().is_empty()) {
        bail!("the file has no header row");
    }
    let custom: Vec<String> = db.custom_fields()?.into_iter().map(|f| f.name).collect();
    let cols: Vec<Col> = headers.iter().map(|h| classify(h, &custom)).collect();
    let mut report = ImportReport { dry_run: opts.dry_run, ..Default::default() };
    for (h, c) in headers.iter().zip(&cols) {
        match c {
            Col::Key(_) => report.key_columns.push(h.clone()),
            Col::Ignored => report.ignored_columns.push(h.clone()),
            _ => report.update_columns.push(h.clone()),
        }
    }
    if report.key_columns.is_empty() {
        bail!("no identifier column found — include one of: id, asset_tag, serial_number, mac, ip, name");
    }
    let sites: HashMap<String, i64> = db.list_sites()?.into_iter().map(|s| (s.name.to_lowercase(), s.id)).collect();
    let mut assets = db.list_assets(&AssetFilter::default())?;

    for (i, rec) in rdr.records().enumerate() {
        let row = i + 1;
        report.rows += 1;
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                report.skipped += 1;
                report.results.push(RowResult { row, asset_id: None, asset: None, action: "skipped".into(), changes: vec![], errors: vec![format!("unreadable row: {e}")] });
                continue;
            }
        };
        // Undo the formula-injection guard our CSV export adds ('=… → =…) so round-trips are lossless.
        let cell = |idx: usize| {
            let v = rec.get(idx).unwrap_or("").trim();
            match v.strip_prefix('\'') {
                Some(rest) if rest.starts_with(['=', '+', '-', '@']) => rest.to_string(),
                _ => v.to_string(),
            }
        };
        let mut res = RowResult { row, asset_id: None, asset: None, action: String::new(), changes: vec![], errors: vec![] };

        // 1. Match.
        let mut matched: Option<i64> = None;
        let mut match_err = None;
        for key in KEYS {
            if let Some(idx) = cols.iter().position(|c| *c == Col::Key(key)) {
                let v = cell(idx);
                if v.is_empty() {
                    continue;
                }
                match find_asset(&assets, key, &v) {
                    Ok(Some(id)) => {
                        matched = Some(id);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        match_err = Some(e.to_string());
                        break;
                    }
                }
            }
        }
        if let Some(e) = match_err {
            res.action = "skipped".into();
            res.errors.push(e);
            report.skipped += 1;
            report.results.push(res);
            continue;
        }
        let get_key = |k: &str| cols.iter().position(|c| *c == Col::Key(match k { "ip" => "ip", "mac" => "mac", _ => "name" })).map(cell).filter(|v| !v.is_empty());
        let asset_id = match matched {
            Some(id) => {
                report.matched += 1;
                res.action = "updated".into();
                id
            }
            None if opts.create_missing => {
                let (ip, mac, name) = (get_key("ip"), get_key("mac"), get_key("name"));
                if ip.is_none() && mac.is_none() && name.is_none() {
                    res.action = "skipped".into();
                    res.errors.push("no matching asset, and no ip/mac/name to create one".into());
                    report.skipped += 1;
                    report.results.push(res);
                    continue;
                }
                report.created += 1;
                res.action = "created".into();
                if opts.dry_run {
                    res.asset = name.clone().or(ip.clone()).or(mac.clone());
                    res.changes.push("new asset".into());
                    report.results.push(res);
                    continue;
                }
                match db.create_manual_asset(ip.as_deref(), mac.as_deref(), name.as_deref(), &opts.source) {
                    Ok(id) => {
                        if let Some(a) = db.get_asset(id)? {
                            assets.push(a);
                        }
                        id
                    }
                    Err(e) => {
                        report.created -= 1;
                        report.skipped += 1;
                        res.action = "skipped".into();
                        res.errors.push(format!("could not create asset: {e:#}"));
                        report.results.push(res);
                        continue;
                    }
                }
            }
            None => {
                res.action = "skipped".into();
                res.errors.push("no matching asset (enable 'create missing' to add it)".into());
                report.skipped += 1;
                report.results.push(res);
                continue;
            }
        };
        let current = assets.iter().find(|a| a.id == asset_id).cloned();
        res.asset_id = Some(asset_id);
        res.asset = current.as_ref().map(|a| a.display_name());

        // 2. Collect edits. asset_tag/serial_number columns also update the field when the row
        // matched on a different key (e.g. matched by IP, filling in the serial).
        let mut edits: Vec<(String, Option<String>)> = Vec::new();
        let mut custom_edits: Vec<(String, Option<String>)> = Vec::new();
        let mut site_edit: Option<Option<i64>> = None;
        for (idx, col) in cols.iter().enumerate() {
            let raw = cell(idx);
            if raw.is_empty() {
                continue;
            }
            let clear = raw == "-";
            match col {
                Col::Field(c) | Col::Key(c @ ("asset_tag" | "serial_number")) => {
                    match if clear { Ok(None) } else { normalize_field(c, &raw) } {
                        Ok(v) => edits.push((c.to_string(), v)),
                        Err(e) => res.errors.push(format!("{}: {e}", headers[idx])),
                    }
                }
                Col::Custom(name) => custom_edits.push((name.clone(), (!clear).then(|| raw.clone()))),
                Col::Site => {
                    if clear || raw.eq_ignore_ascii_case("auto") {
                        site_edit = Some(None);
                    } else if let Some(id) = sites.get(&raw.to_lowercase()) {
                        // Same site it's already in → leave as is (so re-importing an export doesn't pin everything).
                        if current.as_ref().map(|a| a.site_id) != Some(Some(*id)) {
                            site_edit = Some(Some(*id));
                        }
                    } else {
                        res.errors.push(format!("site: no site named '{raw}'"));
                    }
                }
                _ => {}
            }
        }

        // 3. Diff (and apply unless dry run).
        if let Some(a) = &current {
            for (c, v) in &edits {
                let old = a.editable(c);
                if old.as_deref() != v.as_deref() {
                    res.changes.push(format!("{c}: {} → {}", old.as_deref().unwrap_or("∅"), v.as_deref().unwrap_or("∅")));
                }
            }
            if let Some(s) = site_edit {
                let want_manual = s.is_some();
                if s != a.site_id || want_manual != a.site_manual {
                    res.changes.push(format!("site → {}", s.and_then(|id| sites.iter().find(|(_, v)| **v == id).map(|(k, _)| k.clone())).unwrap_or_else(|| "automatic".into())));
                }
            }
        }
        let existing_custom: HashMap<String, String> = db.asset_custom_values(asset_id)?.into_iter().map(|(k, v)| (k.to_lowercase(), v)).collect();
        for (name, v) in &custom_edits {
            let old = existing_custom.get(&name.to_lowercase());
            if old.map(String::as_str) != v.as_deref() {
                res.changes.push(format!("{name}: {} → {}", old.map(String::as_str).unwrap_or("∅"), v.as_deref().unwrap_or("∅")));
            }
        }
        if !opts.dry_run {
            db.update_asset_fields(asset_id, &edits)?;
            for (name, v) in &custom_edits {
                if let Err(e) = db.set_custom_value(asset_id, name, v.as_deref()) {
                    res.errors.push(format!("{name}: {e}"));
                }
            }
            if let Some(s) = site_edit {
                db.set_asset_site(asset_id, s)?;
            }
        }
        if !res.changes.is_empty() {
            report.fields_changed += res.changes.len();
            if res.action == "updated" {
                report.updated_assets += 1;
            }
        } else if res.action == "updated" {
            res.action = "unchanged".into();
        }
        report.results.push(res);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::HostResult;

    fn db() -> Db {
        let db = Db::open(":memory:").unwrap();
        let scan = db.create_scan_for_site("x", "test", None).unwrap();
        for (ip, mac, name) in [("10.1.0.5", "00:14:22:00:00:05", "FD-01"), ("10.1.0.6", "00:14:22:00:00:06", "FD-02"), ("10.1.0.7", "00:14:22:00:00:07", "FD-02")] {
            let h = HostResult { ip: ip.parse().unwrap(), alive: true, mac: Some(mac.into()), netbios_name: Some(name.into()), detected_by: vec!["tcp"], ..Default::default() };
            db.record_host(scan, &h).unwrap();
        }
        db.add_site("Billing Office", "10.1.0.0/24", "").unwrap();
        db.add_custom_field("Insurance Plan").unwrap();
        db
    }

    #[test]
    fn updates_by_various_keys() {
        let db = db();
        let csv = "IP Address,Serial,Owner,Dept,Warranty,Insurance Plan,vendor\n\
                   10.1.0.5,SN-111,Jane Doe,Billing,12/31/2027,Gold,IGNORED\n\
                   ,,,,,,\n";
        let r = import_csv(&db, csv, &ImportOptions { dry_run: true, ..Default::default() }).unwrap();
        assert_eq!(r.matched, 1);
        assert_eq!(r.ignored_columns, vec!["vendor"]);
        assert_eq!(r.results[0].changes.len(), 5, "{:?}", r.results[0].changes);
        assert!(db.list_assets(&AssetFilter::default()).unwrap().iter().all(|a| a.owner.is_none()), "dry run writes nothing");

        let r = import_csv(&db, csv, &ImportOptions::default()).unwrap();
        assert_eq!(r.updated_assets, 1);
        let a = db.list_assets(&AssetFilter { q: Some("SN-111".into()), ..Default::default() }).unwrap().remove(0);
        assert_eq!(a.owner.as_deref(), Some("Jane Doe"));
        assert_eq!(a.department.as_deref(), Some("Billing"));
        assert_eq!(a.warranty_end.as_deref(), Some("2027-12-31"));
        assert_eq!(db.asset_custom_values(a.id).unwrap(), vec![("Insurance Plan".into(), "Gold".into())]);

        // Now match by serial, clear the owner with "-", leave dept untouched.
        let r = import_csv(&db, "serial_number,owner,department\nSN-111,-,\n", &ImportOptions::default()).unwrap();
        assert_eq!(r.fields_changed, 1);
        let a = db.get_asset(a.id).unwrap().unwrap();
        assert!(a.owner.is_none());
        assert_eq!(a.department.as_deref(), Some("Billing"));
        // Edits are in the change log.
        assert!(db.changes(Some(a.id), 50).unwrap().iter().any(|c| c.field == "owner" && c.new_value.is_none()));
        // Re-import with same values → unchanged.
        let r = import_csv(&db, "id,department\n1,Billing\n", &ImportOptions::default()).unwrap();
        assert_eq!(r.results[0].action, "unchanged");
    }

    #[test]
    fn ambiguity_errors_and_creation() {
        let db = db();
        let csv = "name,owner,purchase_date,site\nFD-02,Bob,2025-02-30,Billing Office\nFD-01,Ann,2024-01-15,Nowhere\nLAPTOP-99,Cara,,\n";
        let r = import_csv(&db, csv, &ImportOptions::default()).unwrap();
        assert!(r.results[0].errors[0].contains("matches 2 assets"));
        assert_eq!(r.results[1].action, "updated");
        assert!(r.results[1].errors.iter().any(|e| e.contains("no site named")));
        assert_eq!(r.results[2].action, "skipped");

        let r = import_csv(&db, "name,ip,mac,owner,site\nLAPTOP-99,,AA-BB-CC-00-11-22,Cara,Billing Office\n",
            &ImportOptions { create_missing: true, source: "import".into(), ..Default::default() }).unwrap();
        assert_eq!(r.created, 1);
        let a = db.get_asset(r.results[0].asset_id.unwrap()).unwrap().unwrap();
        assert_eq!(a.display_name(), "LAPTOP-99");
        assert_eq!(a.mac.as_deref(), Some("AA:BB:CC:00:11:22"));
        assert_eq!(a.source, "import");
        assert_eq!(a.owner.as_deref(), Some("Cara"));
        assert!(a.site_manual, "site column pins the asset");

        let bad = "name,owner,purchase_date\nFD-01,Ann,not-a-date\n";
        let r = import_csv(&db, bad, &ImportOptions::default()).unwrap();
        assert!(r.results[0].errors[0].contains("not a date"));
        assert!(import_csv(&db, "owner\nx\n", &ImportOptions::default()).is_err(), "needs an identifier column");
    }

    #[test]
    fn export_roundtrip_is_a_no_op_then_applies_edits() {
        let db = db();
        let a = db.list_assets(&AssetFilter::default()).unwrap()[0].clone();
        db.update_asset_fields(a.id, &[("owner".into(), Some("=SUM(1)".into()))]).unwrap();
        let csv = crate::web::assets_csv(&db, &db.list_assets(&AssetFilter::default()).unwrap()).unwrap();
        let r = import_csv(&db, &csv, &ImportOptions::default()).unwrap();
        assert_eq!(r.fields_changed, 0, "export → import changes nothing: {:?}", r.results);
        assert_eq!(db.get_asset(a.id).unwrap().unwrap().owner.as_deref(), Some("=SUM(1)"));
        assert!(r.results.iter().all(|x| x.errors.is_empty()), "{:?}", r.results);
        assert!(db.list_assets(&AssetFilter::default()).unwrap().iter().all(|a| !a.site_manual), "re-import must not pin sites");
        // Edit the export like a spreadsheet user would: fill a model column.
        let edited = csv.replacen("\r\n", "\r\n", 1).replace(",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",", ",\"\",\"\",\"\",\"\",\"OptiPlex 7010\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",");
        let r = import_csv(&db, &edited, &ImportOptions::default()).unwrap();
        assert!(r.fields_changed >= 1, "{:?}", r.results);
        assert!(db.list_assets(&AssetFilter::default()).unwrap().iter().any(|a| a.model.as_deref() == Some("OptiPlex 7010")));
    }
}
