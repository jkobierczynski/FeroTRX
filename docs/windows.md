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
started as administrator. The GUI's own server ("This computer", below)
asks for that itself, with a UAC prompt, and only then; the Windows service
runs as LocalSystem and may always use Npcap.

## Sending fast

Npcap needs a trip into its driver for every packet sent on its own, which
limits a run to a few hundred thousand packets per second at most. FeroTRX
hands Npcap 64 packets at a time instead (`pcap_sendqueue_transmit`), one
trip for the lot. Paced streams lose nothing by it: whatever is queued goes
out before the engine waits for the next packet's time, so only runs faster
than the batch can fill (top speed, high rates) are batched at all.
`--batch N` (or `batch = N` in a profile's `[output]`) changes the size, up to
4096; `--batch 1` sends packet by packet as before. The line printed at the
start says which: `sending with pcap on Ethernet 2, batches of 64 (Npcap send queue)`.

To see what batching gives on your machine (send to a switch port or another
machine, not to anything that minds a flood):

```powershell
ferotrx replay examples\web.pcap -i "Ethernet 2" -t -l 0 --duration 10s --batch 1
ferotrx replay examples\web.pcap -i "Ethernet 2" -t -l 0 --duration 10s
ferotrx replay examples\web.pcap -i "Ethernet 2" -t -l 0 --duration 10s --batch 512
```

The receive side (`--rx`, `--latency`, `ferotrx rx`, benchmarks) asks Npcap
for precise system time stamps (`KeQuerySystemTimePrecise`). Npcap's default
time stamps count from the performance counter and drift away from the
system clock the sender stamps its signatures with, which shows up as
latency that creeps up or down over a long run. Npcap releases without
precise time stamps fall back to the default.

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

## The GUI's own server

The GUI shows **This computer** under "Servers and ports" the first time it
starts. **Start** runs the `ferotrx.exe` installed next to it as a server
of the GUI's own: on 127.0.0.1 at a port Windows picks, with a token made
up for this session (so no other user or program on the machine can use
it), and without a console window. It stops when you click **Stop**, and
when the GUI closes, even if the GUI crashes. Its files, output pcaps and
captures can be any under your user folder (and the installed examples);
**Edit…** gives it other folders. Details are in [the GUI guide](gui.md#this-computer).

When Npcap is for administrators only, **Start** asks with a UAC prompt to
start the server as administrator; otherwise it starts as you, with no
prompt.

## The Windows service

To keep a server running from boot, without anyone logged in (for a test
box that a GUI or `ferotrx ctl` elsewhere drives), install it as a service
from a terminal started as administrator:

```powershell
# On this computer only, with a token:
ferotrx service install -- --token SECRET

# Reachable from the lab, over TLS with client certificates (remote-control.md):
ferotrx service install -- --listen 0.0.0.0:4510 --tls-cert C:\ferotrx\server.pem `
    --tls-key C:\ferotrx\server-key.pem --client-ca C:\ferotrx\ca.pem

ferotrx service status
ferotrx service stop
ferotrx service start
ferotrx service remove
```

Everything after `--` is given to `ferotrx serve`. The service is called
`FeroTRX` (in **Services**, or `sc query FeroTRX`), starts at boot (or with
`--manual` only on `ferotrx service start`; `--no-start` installs it
without starting it) and runs as LocalSystem. Its folder is
`%ProgramData%\FeroTRX`:

| File | What |
| --- | --- |
| `data\` | The data directory, when `--data-dir` is not given: profiles, pcaps and output files clients name. |
| `audit.log` | The audit log (logins, refusals, runs), when `--audit-log` is not given. |
| `tokens.toml` | Tokens given with `--token` and `--read-token`, as SHA-256 only: a service's command line can be read by every user, so the tokens are not left on it. |
| `service.log` | When the service started, stopped, and why it could not start. |

The installer stops the service while it replaces `ferotrx.exe` (start it
again after an upgrade with `ferotrx service start`), and removes it when
FeroTRX is uninstalled. `ferotrx service remove` leaves the folder.

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
the `*.ferotrx` association), runs `ferotrx.exe` from it without Npcap,
installs, uses and removes the service, starts the GUI's own server, and
uninstalls it.
