//! On Windows: the icon, version information and manifest of ferotrx-gui.exe.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../packaging/windows/ferotrx.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/ferotrx.manifest");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../packaging/windows/ferotrx.ico")
            .set_manifest_file("../../packaging/windows/ferotrx.manifest")
            .set("ProductName", "FeroTRX")
            .set("FileDescription", "FeroTRX GUI")
            .set("LegalCopyright", "FeroTRX contributors, GPL-3.0-or-later");
        res.compile()
            .expect("cannot embed the Windows resources (rc.exe from the Windows SDK)");
    }
}
