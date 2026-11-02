//! Compiles the DPDK shim when the `dpdk` feature is on. Nothing to do otherwise.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "dpdk")]
    dpdk::build();
}

#[cfg(feature = "dpdk")]
mod dpdk {
    pub fn build() {
        println!("cargo:rerun-if-changed=src/dpdk/shim.c");
        println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
        let lib = match pkg_config::Config::new()
            .atleast_version("21.11")
            .cargo_metadata(true)
            .probe("libdpdk")
        {
            Ok(lib) => lib,
            Err(e) => panic!(
                "the `dpdk` feature needs DPDK 21.11 or newer with its pkg-config file \
                 (libdpdk.pc), e.g. `apt install dpdk-dev` or `ninja install` from a DPDK \
                 build, with PKG_CONFIG_PATH pointing at it: {e}"
            ),
        };
        let mut build = cc::Build::new();
        build.file("src/dpdk/shim.c").warnings(false);
        for path in &lib.include_paths {
            build.include(path);
        }
        // DPDK's own CFLAGS (-include rte_config.h, -march=...), as pkg-config gives them.
        let cflags = std::process::Command::new(
            std::env::var("PKG_CONFIG").unwrap_or_else(|_| "pkg-config".into()),
        )
        .args(["--cflags", "libdpdk"])
        .output()
        .expect("cannot run pkg-config");
        for flag in String::from_utf8_lossy(&cflags.stdout).split_whitespace() {
            if !flag.starts_with("-I") {
                build.flag(flag);
            }
        }
        build.compile("ferotrx_dpdk_shim");
    }
}
