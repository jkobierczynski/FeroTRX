//! On Windows: the icon, version information and manifest of ferotrx.exe,
//! and Npcap's wpcap.dll loaded late, so that ferotrx.exe starts without
//! Npcap (file and null outputs, `serve`, `ctl`) and says what is missing
//! when an interface is asked for (ferotrx_io::windows::load_npcap).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../packaging/windows/ferotrx.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/ferotrx.manifest");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc && std::env::var_os("CARGO_FEATURE_PCAP").is_some() {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
    #[cfg(windows)]
    if windows {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../packaging/windows/ferotrx.ico")
            .set_manifest_file("../../packaging/windows/ferotrx.manifest")
            .set("ProductName", "FeroTRX")
            .set("FileDescription", "FeroTRX traffic generator")
            .set("LegalCopyright", "FeroTRX contributors, GPL-3.0-or-later");
        res.compile()
            .expect("cannot embed the Windows resources (rc.exe from the Windows SDK)");
    }
}
