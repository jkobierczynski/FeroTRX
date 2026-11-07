# Installing and building

## Packages

Every release on the [Releases page](https://github.com/jkobierczynski/FeroTRX/releases)
has ready-made packages:

* **Debian and Ubuntu (x86_64):** download `ferotrx_*_amd64.deb` and run
  `sudo apt install ./ferotrx_*_amd64.deb`.
* **Other Linux, macOS:** unpack the `.tar.gz` for your system and put `ferotrx` on your `PATH`
  (Linux needs libpcap: `libpcap0.8` on Debian, `libpcap` elsewhere).
* **Windows:** run the `.msi` installer (or unpack the `.zip`); install
  [Npcap](https://npcap.com/) to send and receive. See [Windows](windows.md).

The packages have the default backends (libpcap/Npcap, and AF_XDP on Linux).
For DPDK, build from source. How releases are made: [RELEASING.md](../RELEASING.md).

## Building from source

You need a stable Rust toolchain and libpcap:

* **Linux:** `sudo apt install libpcap-dev` (or your distribution's package).
* **macOS:** libpcap ships with the OS.
* **Windows:** put the Npcap SDK's `Lib\x64` folder on the `LIB` path to
  build, and install [Npcap](https://npcap.com/) to use interfaces (the
  programs start without it). `packaging\windows\build-msi.ps1` builds the
  installer ([Windows](windows.md#building-the-installer)).

```sh
cargo build --release
```

The desktop GUI is its own binary (see [the GUI guide](gui.md)); it needs no
libpcap, only a graphics driver with OpenGL:
`cargo build --release -p ferotrx-gui` (`target/release/ferotrx-gui`). On
Linux it runs on X11 or Wayland.

To build without libpcap (file and null output only):
`cargo build -p ferotrx-cli --no-default-features`.

AF_XDP support is built in on Linux and needs no extra libraries. DPDK support
is optional: install DPDK 21.11 or newer with its pkg-config file
(`sudo apt install dpdk-dev` on Debian and Ubuntu) and build with
`cargo build --release --features dpdk`. `ferotrx backends` shows what a build has.

## Permissions

Sending on an interface needs root or `CAP_NET_RAW` on Linux, access to
`/dev/bpf*` on macOS, and Npcap on Windows.
