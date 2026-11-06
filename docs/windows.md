# FeroTRX on Windows

FeroTRX runs on Windows 10 and 11 (x86_64): the `ferotrx` command, the
control server (`ferotrx serve`) and the desktop GUI (`ferotrx-gui`).
Interfaces are sent on and received from through
[Npcap](https://npcap.com/). AF_XDP, DPDK and the lab router are Linux only;
a Windows GUI can drive a Linux server for those (see [the GUI](gui.md)).

## Installing

Every release has an installer, `ferotrx-vX.Y.Z-x86_64-windows.msi`, and the
same programs as a `.zip`.

The installer puts in `Program Files\FeroTRX`:

* `ferotrx-gui.exe`, with a **FeroTRX** entry in the Start menu (it starts
  in your Documents folder);
* `ferotrx.exe`, with the folder added to the system `PATH`, so `ferotrx`
  works in any new terminal;
* the examples and this manual (`examples\`, `docs\`), `README.md` and
  `LICENSE.txt`;
* workspace files (`*.ferotrx`) open in the GUI when double-clicked.

A newer installer replaces an older version in place; **Apps** in Windows
settings removes it. For a silent install:
`msiexec /i ferotrx-vX.Y.Z-x86_64-windows.msi /qn` (and `/x` to remove).

The installer is not signed yet, so SmartScreen may warn about an
unknown publisher (**More info**, **Run anyway**).

## Npcap

Install [Npcap](https://npcap.com/) to send and receive on interfaces; its
free licence does not allow bundling it, so it is a separate download. Its
default options are fine; "WinPcap API-compatible mode" is not needed, as
FeroTRX loads `wpcap.dll` from `System32\Npcap` itself.

Without Npcap everything else still works: profiles to the `file` and
`null` outputs, `inspect`, `build`, `check`, `serve` and `ctl`. Asking for
an interface says what is missing:

```text
> ferotrx interfaces
Error: cannot list interfaces

Caused by:
    Npcap is not installed (wpcap.dll not found): install it from https://npcap.com ...
```

If Npcap was installed with "Restrict Npcap driver's access to
Administrators only", run `ferotrx` (or `ferotrx serve`) from a terminal
started as administrator.

## Interface names

Npcap names an interface `\Device\NPF_{GUID}`. FeroTRX also takes the name
Windows shows in its network settings, in any case:

```text
> ferotrx interfaces
Ethernet 2   \Device\NPF_{1F3A...}   Realtek Gaming 5GbE Family Controller   00:e0:4c:68:01:02   192.168.1.20 fe80::...
Wi-Fi        \Device\NPF_{88C1...}   Intel(R) Wi-Fi 6 AX201 160MHz            ...

> ferotrx run examples\lab-two-vlans.toml -i "Ethernet 2"
```

The GUI lists ports by these names too, with the Npcap name, MAC and
addresses in the tooltip. A profile's `[output]` and the control API take
either form.

## The GUI

`ferotrx-gui.exe` is a window, not a console program. Started from a
terminal, its `--help` and errors still print there. It uses Explorer's own
file dialogs (set `FEROTRX_GUI_DIALOGS=egui` for the ones drawn in the
window), and keeps its state, theme and window layout in
`%APPDATA%\FeroTRX`.

It draws with OpenGL, which needs a graphics driver: on a virtual machine
or remote desktop without one, it may not start.

Use **Appearance…** in the top bar for colours, widget style and text
sizes (see [the GUI guide](gui.md#appearance)).

## Building the installer

On Windows, with Rust, the Npcap SDK on `LIB` (see [installing](install.md))
and the .NET SDK:

```powershell
cargo build --release -p ferotrx-cli -p ferotrx-gui
packaging\windows\build-msi.ps1          # dist\ferotrx-vX.Y.Z-x86_64-windows.msi
```

The script installs the [WiX Toolset](https://wixtoolset.org/) 5 (a .NET
tool) when it is missing. The installer is described in
`packaging\windows\ferotrx.wxs`; the icon, version information and manifest
of both programs come from `packaging\windows` through their `build.rs`.
CI builds the installer on every pull request, installs it silently,
checks what it installed (programs, examples, `PATH`, the Start menu entry,
the `*.ferotrx` association), runs `ferotrx.exe` from it without Npcap and
uninstalls it.
