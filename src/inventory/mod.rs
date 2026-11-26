//! Credentialed Windows inventory over WMI/CIM.
//!
//! RustSweeper (running on Windows) launches Windows PowerShell with `collect.ps1`, which opens a
//! CIM session to the target — DCOM by default, like Lansweeper — and returns hardware, OS and
//! logged-on-user details as JSON. Passwords are stored DPAPI-encrypted (LocalMachine scope) and
//! only ever handed to the child process through its environment.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize};

use crate::db::{Asset, Credential, Db};

const COLLECT_PS: &str = include_str!("collect.ps1");

const PROTECT_PS: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security
$bytes = [Text.Encoding]::UTF8.GetBytes($env:RSW_PLAIN)
$entropy = [Text.Encoding]::UTF8.GetBytes('RustSweeper')
$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
[Convert]::ToBase64String($enc)
"#;

/// How long one collection may take before it is abandoned.
/// Software enumeration over StdRegProv makes many small WMI calls, so allow a few minutes.
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(240);

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Disk {
    pub drive: Option<String>,
    pub filesystem: Option<String>,
    pub size_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Nic {
    pub description: Option<String>,
    pub mac: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Software {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// Usually YYYYMMDD as written by the installer.
    pub install_date: Option<String>,
    pub arch: Option<String>,
}

impl Software {
    /// Install date as YYYY-MM-DD when the installer wrote a recognisable date.
    pub fn install_date_iso(&self) -> Option<String> {
        let d = self.install_date.as_deref()?.trim();
        let digits: String = d.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 8 {
            let iso = format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..]);
            if chrono::NaiveDate::parse_from_str(&iso, "%Y-%m-%d").is_ok() {
                return Some(iso);
            }
        }
        None
    }
}

/// Group-friendly product name: drops version numbers, architecture/language tags and
/// "(remove only)"-style suffixes, so "Mozilla Firefox (x64 en-US) 128.0.3" → "Mozilla Firefox".
pub fn normalize_product(name: &str) -> String {
    let mut s = name.trim().to_string();
    // Drop bracketed tags: (x64 en-US), (64-bit), [Remove only] …
    loop {
        let before = s.clone();
        for (o, c) in [('(', ')'), ('[', ']')] {
            if let (Some(i), Some(j)) = (s.rfind(o), s.rfind(c)) {
                if i < j && j == s.len() - c.len_utf8() {
                    s.truncate(i);
                    s = s.trim_end().to_string();
                }
            }
        }
        // Drop trailing version-like tokens: 128.0.3, v2.1, 2019, x64, 64-bit, -
        let toks: Vec<&str> = s.split_whitespace().collect();
        if let Some(last) = toks.last() {
            let l = last.to_lowercase();
            let versiony = l.trim_start_matches('v').chars().all(|c| c.is_ascii_digit() || c == '.') && l.chars().any(|c| c.is_ascii_digit()) && (l.contains('.') || l.starts_with('v'));
            // Locale tags such as en-us / fr-FR.
            let locale = l.len() == 5 && l.as_bytes()[2] == b'-' && l.chars().filter(|c| c.is_ascii_alphabetic()).count() == 4;
            if toks.len() > 1 && (versiony || locale || ["x64", "x86", "64-bit", "32-bit", "-", "–", "version"].contains(&l.as_str())) {
                s = toks[..toks.len() - 1].join(" ");
            }
        }
        if s == before {
            break;
        }
    }
    s.trim_end_matches([' ', '-', ',']).to_string()
}

/// "Microsoft Corporation" → "Microsoft", "Google LLC" → "Google".
pub fn normalize_publisher(p: &str) -> String {
    let mut s = p.trim().trim_end_matches('.').to_string();
    for suffix in [", Inc", " Inc", " Corporation", " Corp", " LLC", " Ltd", " Limited", " GmbH", " Incorporated", " Co"] {
        if s.len() > suffix.len() && s.to_lowercase().ends_with(&suffix.to_lowercase()) {
            s.truncate(s.len() - suffix.len());
            s = s.trim_end_matches([',', '.', ' ']).to_string();
        }
    }
    s
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Service {
    pub name: String,
    pub display_name: Option<String>,
    pub state: Option<String>,
    pub start_mode: Option<String>,
    pub start_name: Option<String>,
    pub path: Option<String>,
}

impl Service {
    /// Unquoted executable path containing spaces — a classic privilege-escalation finding.
    pub fn unquoted_path(&self) -> bool {
        let Some(p) = self.path.as_deref().map(str::trim) else { return false };
        if p.starts_with('"') {
            return false;
        }
        match p.to_lowercase().find(".exe") {
            Some(i) => p[..i].contains(' '),
            None => false,
        }
    }

    /// Runs as a real account (domain/local user) rather than a built-in service identity.
    pub fn custom_account(&self) -> bool {
        let Some(n) = self.start_name.as_deref().map(|s| s.trim().to_lowercase()) else { return false };
        !(n.is_empty()
            || n == "localsystem"
            || n.starts_with("nt authority\\")
            || n.starts_with("nt service\\")
            || n == "localservice"
            || n == "networkservice")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AvProduct {
    pub name: Option<String>,
    pub product_state: Option<i64>,
}

impl AvProduct {
    /// Decode Security Center's productState: middle byte 0x10/0x11 = on, low byte 0x00 = definitions up to date.
    pub fn enabled(&self) -> Option<bool> {
        self.product_state.map(|s| matches!((s >> 8) & 0xFF, 0x10 | 0x11))
    }
    pub fn up_to_date(&self) -> Option<bool> {
        self.product_state.map(|s| s & 0xFF == 0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Defender {
    #[serde(default)]
    pub antivirus_enabled: bool,
    #[serde(default)]
    pub realtime_enabled: bool,
    pub signature_updated: Option<String>,
    pub signature_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct BitLockerVolume {
    pub drive: Option<String>,
    /// 0 = off, 1 = on, 2 = unknown (Win32_EncryptableVolume.ProtectionStatus).
    pub protection_status: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Hotfix {
    pub id: Option<String>,
    pub description: Option<String>,
    pub installed_on: Option<String>,
}

impl Hotfix {
    /// InstalledOn comes back as YYYY-MM-DD, M/D/YYYY (string form) or, rarely, garbage.
    pub fn date_iso(&self) -> Option<String> {
        let d = self.installed_on.as_deref()?.trim();
        for f in ["%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y%m%d"] {
            if let Ok(x) = chrono::NaiveDate::parse_from_str(d, f) {
                return Some(x.format("%Y-%m-%d").to_string());
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Firewall {
    pub domain: Option<i64>,
    pub private: Option<i64>,
    pub public: Option<i64>,
}

/// Security posture collected alongside the inventory. `None` lists mean "couldn't read".
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Protection {
    #[serde(default, deserialize_with = "opt_one_or_many")]
    pub antivirus: Option<Vec<AvProduct>>,
    pub defender: Option<Defender>,
    #[serde(default, deserialize_with = "opt_one_or_many")]
    pub bitlocker: Option<Vec<BitLockerVolume>>,
    #[serde(default, deserialize_with = "opt_one_or_many")]
    pub hotfixes: Option<Vec<Hotfix>>,
    pub reboot_pending: Option<bool>,
    pub firewall: Option<Firewall>,
    pub display_version: Option<String>,
    pub ubr: Option<i64>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub errors: Vec<String>,
}

impl Protection {
    /// Is the device protected by an enabled, up-to-date antivirus? None = couldn't tell.
    pub fn av_ok(&self) -> Option<bool> {
        let sc = self.antivirus.as_ref().map(|list| list.iter().any(|a| a.enabled() == Some(true) && a.up_to_date() == Some(true)));
        let def = self.defender.as_ref().map(|d| d.antivirus_enabled && d.realtime_enabled);
        match (sc, def) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (None, None) => None,
            _ => Some(false),
        }
    }

    /// BitLocker protection on the system drive (C:).
    pub fn bitlocker_os(&self) -> Option<bool> {
        let vols = self.bitlocker.as_ref()?;
        let c = vols.iter().find(|v| v.drive.as_deref().is_some_and(|d| d.eq_ignore_ascii_case("C:")))?;
        match c.protection_status {
            Some(1) => Some(true),
            Some(0) => Some(false),
            _ => None,
        }
    }

    /// Any firewall profile switched off?
    pub fn firewall_off(&self) -> Option<bool> {
        let f = self.firewall.as_ref()?;
        let v = [f.domain, f.private, f.public];
        if v.iter().all(Option::is_none) {
            return None;
        }
        Some(v.iter().any(|x| *x == Some(0)))
    }

    pub fn last_patch_date(&self) -> Option<String> {
        self.hotfixes.as_ref()?.iter().filter_map(Hotfix::date_iso).max()
    }
}

fn opt_one_or_many<'de, D, T>(d: D) -> std::result::Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => one_or_many(v).map(Some).map_err(serde::de::Error::custom),
    }
}

/// What `collect.ps1` returns on success.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WinInventory {
    pub computer_name: Option<String>,
    pub domain: Option<String>,
    #[serde(default)]
    pub part_of_domain: bool,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub system_type: Option<String>,
    pub last_user: Option<String>,
    pub memory_bytes: Option<u64>,
    pub logical_processors: Option<u32>,
    pub serial_number: Option<String>,
    pub bios_version: Option<String>,
    pub bios_date: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub os_arch: Option<String>,
    pub os_install_date: Option<String>,
    pub last_boot: Option<String>,
    pub cpu: Option<String>,
    pub cpu_count: Option<u32>,
    pub cores: Option<u32>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub disks: Vec<Disk>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub nics: Vec<Nic>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub software: Vec<Software>,
    pub software_error: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub services: Vec<Service>,
    pub services_error: Option<String>,
    pub protection: Option<Protection>,
}

impl WinInventory {
    pub fn memory_mb(&self) -> Option<i64> {
        self.memory_bytes.map(|b| (b / (1024 * 1024)) as i64)
    }

    /// Lowest free-space percentage across fixed disks.
    pub fn min_free_pct(&self) -> Option<f64> {
        self.disks
            .iter()
            .filter_map(|d| match (d.size_bytes, d.free_bytes) {
                (Some(s), Some(f)) if s > 0 => Some((f as f64 / s as f64 * 1000.0).round() / 10.0),
                _ => None,
            })
            .reduce(f64::min)
    }

    pub fn is_server(&self) -> bool {
        self.os_name.as_deref().is_some_and(|o| o.contains("Server"))
    }

    pub fn is_virtual(&self) -> bool {
        let m = format!("{} {}", self.manufacturer.as_deref().unwrap_or(""), self.model.as_deref().unwrap_or("")).to_lowercase();
        ["vmware", "virtual machine", "virtualbox", "kvm", "qemu", "hvm domu", "xen"].iter().any(|k| m.contains(k))
    }

    /// Serial numbers like "To be filled by O.E.M." are placeholders, not data.
    pub fn real_serial(&self) -> Option<String> {
        let s = self.serial_number.as_deref()?.trim();
        let l = s.to_lowercase();
        if s.is_empty() || l.contains("o.e.m") || l.contains("default string") || l == "none" || l == "0" || l == "system serial number" {
            return None;
        }
        Some(s.to_string())
    }
}

/// PowerShell 5.1's ConvertTo-Json renders arrays inconsistently: a plain array, a bare object
/// (single element), or `{"value":[...],"Count":n}` (arrays carrying ETS properties). Accept all.
fn one_or_many<'de, D, T>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        // Must come before One: an all-optional struct would otherwise "match" the wrapper object.
        Wrapped {
            value: Vec<T>,
        },
        // A list nested in a list (PowerShell's unary-comma array wrapping).
        Nested(Vec<Vec<T>>),
        One(T),
        None,
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        Some(OneOrMany::Many(v)) | Some(OneOrMany::Wrapped { value: v }) => v,
        Some(OneOrMany::Nested(v)) => v.into_iter().flatten().collect(),
        Some(OneOrMany::One(t)) => vec![t],
        _ => vec![],
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum CollectError {
    /// Couldn't reach WMI on the target (offline, firewall, RPC unavailable) — other credentials won't help.
    Unreachable(String),
    /// Reached the target but the credentials were refused.
    AccessDenied(String),
    Other(String),
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
            Self::AccessDenied(m) => write!(f, "access denied: {m}"),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

fn categorise(stage: &str, msg: &str) -> CollectError {
    let l = msg.to_lowercase();
    if l.contains("access is denied") || l.contains("0x80070005") || l.contains("logon failure") || l.contains("user name or password") {
        CollectError::AccessDenied(msg.to_string())
    } else if stage == "connect"
        && (l.contains("rpc server is unavailable") || l.contains("0x800706ba") || l.contains("timed out") || l.contains("timeout")
            || l.contains("cannot find the computer") || l.contains("network path was not found") || l.contains("winrm cannot complete"))
    {
        CollectError::Unreachable(msg.to_string())
    } else {
        CollectError::Other(format!("{stage}: {msg}"))
    }
}

/// Parse collect.ps1 output (tolerates warnings/banners before the JSON line).
pub fn parse_output(stdout: &str) -> std::result::Result<WinInventory, CollectError> {
    // The JSON object starts at the first line beginning with '{' (warnings may precede it) and may
    // span several lines; read exactly one JSON value from there.
    let start = if stdout.trim_start().starts_with('{') {
        stdout.find('{')
    } else {
        stdout.find("\n{").map(|i| i + 1)
    }
    .ok_or_else(|| CollectError::Other(format!("collector returned no JSON: {}", stdout.trim().chars().take(300).collect::<String>())))?;
    let v: serde_json::Value = serde_json::Deserializer::from_str(&stdout[start..])
        .into_iter::<serde_json::Value>()
        .next()
        .ok_or_else(|| CollectError::Other("collector returned no JSON".into()))?
        .map_err(|e| CollectError::Other(format!("bad collector JSON: {e}")))?;
    if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        let stage = v.get("stage").and_then(|s| s.as_str()).unwrap_or("collect");
        let err = v.get("error").and_then(|s| s.as_str()).unwrap_or("unknown error");
        return Err(categorise(stage, err));
    }
    serde_json::from_value(v).map_err(|e| CollectError::Other(format!("unexpected collector output: {e}")))
}

/// Strip full-line comments and indentation so the encoded script stays well inside Windows'
/// 32,767-character command-line limit. (The script has no here-strings, so this is safe.)
pub fn minify(script: &str) -> String {
    script
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `powershell -EncodedCommand` takes base64 of UTF-16LE.
pub fn encode_command(script: &str) -> String {
    let script = minify(script);
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn supported() -> bool {
    cfg!(windows)
}

async fn run_powershell(script: &str, env: &[(&str, &str)], timeout: Duration) -> Result<String> {
    if !supported() {
        bail!("Windows inventory needs RustSweeper running on Windows (it uses Windows PowerShell and WMI)");
    }
    let mut cmd = tokio::process::Command::new("powershell.exe");
    cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode_command(script)]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| anyhow!("timed out after {}s", timeout.as_secs()))?
        .context("could not start powershell.exe")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Encrypt a password with DPAPI (LocalMachine scope) for storage.
pub async fn protect_secret(plain: &str) -> Result<String> {
    let out = run_powershell(PROTECT_PS, &[("RSW_PLAIN", plain)], Duration::from_secs(30)).await?;
    let blob = out.trim().to_string();
    if blob.is_empty() || base64::engine::general_purpose::STANDARD.decode(&blob).is_err() {
        bail!("could not encrypt the password with DPAPI");
    }
    Ok(blob)
}

pub async fn collect(target: &str, cred: Option<&Credential>, protocol: &str) -> std::result::Result<WinInventory, CollectError> {
    let mut env = vec![("RSW_TARGET", target.to_string()), ("RSW_PROTOCOL", protocol.to_string())];
    if let Some(c) = cred {
        env.push(("RSW_USER", c.username.clone()));
        env.push(("RSW_SECRET", c.secret.clone()));
    }
    let env_ref: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    match run_powershell(COLLECT_PS, &env_ref, COLLECT_TIMEOUT).await {
        Ok(out) => match parse_output(&out) {
            // Keep the raw collector output (no secrets in it) so format problems can be diagnosed.
            Err(CollectError::Other(m)) if m.contains("collector") => {
                let safe: String = target.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
                let path = std::env::temp_dir().join(format!("rustsweeper-collector-{safe}.json"));
                match std::fs::write(&path, &out) {
                    Ok(()) => Err(CollectError::Other(format!("{m} (raw output saved to {})", path.display()))),
                    Err(_) => Err(CollectError::Other(m)),
                }
            }
            other => other,
        },
        Err(e) if e.to_string().contains("timed out") => Err(CollectError::Unreachable(e.to_string())),
        Err(e) => Err(CollectError::Other(format!("{e:#}"))),
    }
}

#[derive(Debug, Clone)]
pub struct InventoryOptions {
    /// Dcom (default) or Wsman.
    pub protocol: String,
    /// Try the service's own Windows account after stored credentials.
    pub integrated_auth: bool,
    pub concurrency: usize,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        Self { protocol: "Dcom".into(), integrated_auth: true, concurrency: 8 }
    }
}

/// Does this asset look like something WMI inventory applies to?
pub fn is_candidate(a: &Asset) -> bool {
    if a.status == "offline" || a.ip.is_empty() {
        return false;
    }
    let os = a.os_guess.as_deref().unwrap_or("");
    let t = a.device_type.as_deref().unwrap_or("");
    os.starts_with("Windows") || t.starts_with("Windows") || a.netbios_name.is_some()
}

/// Credentials to try for an asset, in order: the one that worked last time, site-specific,
/// global, then (optionally) the service's own account (`None`).
pub fn credential_order(creds: &[Credential], a: &Asset, last_ok: Option<i64>, integrated: bool) -> Vec<Option<Credential>> {
    let mut list: Vec<Option<Credential>> = Vec::new();
    let mut push = |c: &Credential| {
        if !list.iter().any(|x| x.as_ref().map(|x| x.id) == Some(c.id)) {
            list.push(Some(c.clone()));
        }
    };
    if let Some(id) = last_ok {
        if let Some(c) = creds.iter().find(|c| c.id == id && (c.site_id.is_none() || c.site_id == a.site_id)) {
            push(c);
        }
    }
    for c in creds.iter().filter(|c| c.site_id.is_some() && c.site_id == a.site_id) {
        push(c);
    }
    for c in creds.iter().filter(|c| c.site_id.is_none()) {
        push(c);
    }
    if integrated {
        list.push(None);
    }
    list
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub asset_id: i64,
    pub name: String,
    pub ok: bool,
    pub credential: Option<String>,
    pub message: String,
}

/// Inventory one asset, trying credentials in order; records success or the error on the asset.
pub async fn inventory_asset(db: &Db, a: &Asset, opts: &InventoryOptions) -> Result<Outcome> {
    let creds = db.list_credentials_with_secrets()?;
    let order = credential_order(&creds, a, db.last_inventory_credential(a.id)?, opts.integrated_auth);
    let name = a.display_name();
    if order.is_empty() {
        let msg = "no credentials configured (add one, or allow the service account)".to_string();
        db.record_inventory_error(a.id, &msg)?;
        return Ok(Outcome { asset_id: a.id, name, ok: false, credential: None, message: msg });
    }
    let mut errors = Vec::new();
    for cred in &order {
        let label = cred.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| "service account".into());
        match collect(&a.ip, cred.as_ref(), &opts.protocol).await {
            Ok(inv) => {
                // Make sure the IP still belongs to the device we think it does.
                if let (Some(nb), Some(cn)) = (&a.netbios_name, &inv.computer_name) {
                    if !nb.eq_ignore_ascii_case(cn) {
                        let msg = format!("{} now answers as '{cn}', not '{nb}' — IP reassigned? Rescan first.", a.ip);
                        db.record_inventory_error(a.id, &msg)?;
                        return Ok(Outcome { asset_id: a.id, name, ok: false, credential: Some(label), message: msg });
                    }
                }
                db.save_windows_inventory(a.id, &inv, cred.as_ref().map(|c| c.id), &label)?;
                return Ok(Outcome {
                    asset_id: a.id,
                    name,
                    ok: true,
                    credential: Some(label),
                    message: format!(
                        "{} · {} · {}",
                        inv.os_name.as_deref().unwrap_or("?"),
                        inv.model.as_deref().unwrap_or("?"),
                        inv.last_user.as_deref().unwrap_or("no user logged on")
                    ),
                });
            }
            Err(CollectError::Unreachable(m)) => {
                errors.push(format!("unreachable: {m}"));
                break; // other credentials won't help
            }
            Err(e) => errors.push(format!("{label}: {e}")),
        }
    }
    let msg = errors.join(" | ");
    db.record_inventory_error(a.id, &msg)?;
    Ok(Outcome { asset_id: a.id, name, ok: false, credential: None, message: msg })
}

/// Inventory many assets concurrently. Returns one outcome per asset.
pub async fn inventory_many(db: Db, assets: Vec<Asset>, opts: InventoryOptions) -> Vec<Outcome> {
    use futures::stream::{self, StreamExt};
    let opts = Arc::new(opts);
    stream::iter(assets)
        .map(|a| {
            let db = db.clone();
            let opts = opts.clone();
            async move {
                match inventory_asset(&db, &a, &opts).await {
                    Ok(o) => o,
                    Err(e) => Outcome { asset_id: a.id, name: a.display_name(), ok: false, credential: None, message: format!("{e:#}") },
                }
            }
        })
        .buffer_unordered(opts.concurrency.max(1))
        .collect()
        .await
}

#[cfg(test)]
mod tests;
