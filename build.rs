//! Embeds the application icon and version info into rustsweeper.exe on Windows,
//! so Explorer, the taskbar and desktop shortcuts show the RustLandSweeper shield.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icons/rustlandsweeper.ico");
    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/icons/rustlandsweeper.ico")
                .set("ProductName", "RustLandSweeper")
                .set("FileDescription", "RustLandSweeper network inventory");
            // A missing resource compiler shouldn't break the build — just skip the icon.
            if let Err(e) = res.compile() {
                println!("cargo:warning=could not embed the Windows icon ({e}); the build continues without it");
            }
        }
    }
}
