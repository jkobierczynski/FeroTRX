# The desktop GUI

`ferotrx-gui` is a window onto one or more FeroTRX control servers
(`ferotrx serve`), on this machine or elsewhere in the lab. It shows each
server's interfaces as ports, lets you build streams for a port layer by
layer with a live packet view, sends them, starts stateful TCP and UDP runs,
and shows every run's counters in a grid and in rate charts. It is another
client of the [control API](remote-control.md), like `ferotrx ctl` and the
[Python client](python-client.md): whatever it sends is an ordinary profile
that `ferotrx run` sends the same way.

It runs on Linux (X11 and Wayland), macOS and Windows (with an installer,
see [Windows](windows.md)). It needs no privileges itself; the server does
the sending.

```sh
cargo build --release -p ferotrx-cli -p ferotrx-gui

ferotrx-gui                                  # "This computer": Start runs a server here
ferotrx-gui --local                          # ... and starts it right away

sudo ferotrx serve &                         # or a server of your own on 127.0.0.1:4510
ferotrx-gui --connect 127.0.0.1              # connects to it

# A server elsewhere, over TLS with a client certificate (see remote-control.md):
ferotrx-gui --connect 192.168.56.10 --ca ca.pem --cert alice.pem --key alice-key.pem

# Open on a port with a profile's streams, or with a capture:
ferotrx-gui --port enp0s3 --profile examples/lab-two-vlans.toml
ferotrx-gui examples/web.pcap

# Open a workspace saved earlier (or give the file on its own, as Windows
# does when you double-click one):
ferotrx-gui --workspace lab.ferotrx

# With a theme file (see Appearance below):
ferotrx-gui --theme lab-theme.toml
```

`FEROTRX_CTL`, `FEROTRX_CA`, `FEROTRX_CERT`, `FEROTRX_KEY` and
`FEROTRX_TOKEN` work as for `ferotrx ctl`. Tokens are never saved; the rest
(servers, every port's streams and settings, the forms of every tab, the
last port open) is kept between sessions.

## This computer

The first time the GUI starts (and whenever **Add server…** has "This
computer" ticked) it lists **This computer**: a server the GUI starts
itself. **Start** runs the `ferotrx` next to `ferotrx-gui` (or the one on
`PATH`) as

```text
ferotrx serve --listen 127.0.0.1:0 --tokens <session>/tokens.toml \
    --port-file <session>/port --parent <GUI's process id> --data-dir <your home folder>
```

* **127.0.0.1, port 0**: only this computer can reach it, at a port the
  system picks; the server writes it to its port file, and the GUI reads it.
* **A token for this session**: 32 random bytes, kept in the GUI's memory;
  the tokens file holds only its SHA-256. Other users and programs on the
  machine cannot use the server.
* **It stops with the GUI**: **Stop** (right-click) removes the port file,
  which the server watches, and the server also stops when the GUI's
  process ends, even after a crash. Its runs stop with it.
* **Folders**: your home folder (and the installed examples, on Windows)
  unless **Edit…** lists others, one per line. Files there can be picked
  with this computer's file dialogs.
* `<session>` is a folder of its own under the temporary directory, with
  `server.log` (what the server printed: its audit log, errors), removed
  when the server stops.

Sending on interfaces needs rights the GUI asks for only when needed:

* **Windows**: when Npcap was installed for administrators only, **Start**
  starts the server as administrator, with a UAC prompt. Otherwise there is
  no prompt.
* **Linux**: the server needs root or the capabilities to send. Without
  them, the server shows the command that gives them once:
  `sudo setcap cap_net_raw,cap_net_admin+eip $(command -v ferotrx)`. The
  `file` and `null` ports work without.
* **macOS**: your user needs the BPF devices (`/dev/bpf*`), as Wireshark's
  ChmodBPF sets up; or run `sudo ferotrx serve` and connect to it.

For the lab router, AF_XDP or DPDK, use a server on Linux (`sudo ferotrx
serve --lab` there): the GUI shows only what each server can do, so a
server on Windows or macOS has no **Lab router** entry and only the
backends its build has.

## Appearance

**Appearance…** in the top bar opens a window that changes the look while
you watch; the button next to it switches between following the system,
light and dark.

* **Theme:** a built-in theme to start from (FeroTRX; the plain grey and
  white Neutral, Paper, Slate, Graphite and Dim, made for reading; High
  contrast, Compact and egui's own), its name, and **Open…**/**Save as…** for theme files.
* **Mode:** follow the system, or always light or dark.
* **Colours**, separately for light and dark mode: accent (links, hovered
  outlines, the cursor, the text of selected items), selection, background,
  windows, input fields, table stripes, widgets, hovered widgets, borders,
  and the colours of passed, running, warnings and errors used in every
  tab; optionally your own text colour.
* **Widgets:** corner radius of widgets and of windows, border width,
  density (spacing and widget heights), borders on buttons and fields,
  shadows, animations, scroll bars beside the content instead of floating.
* **Text:** zoom of the whole window (Ctrl + and Ctrl - change it too),
  the font for text and the one for monospace text (packets, profiles,
  logs): System default (this computer's interface fonts: Segoe UI and
  Consolas on Windows, San Francisco on macOS, Noto or DejaVu on Linux),
  egui's built-in fonts, one of the fonts installed on this computer, or a
  `.ttf`/`.otf` file typed in; and the sizes of body, monospace, heading
  and small text. A file that is not a font is refused with a message, and
  the built-in fonts stay behind the chosen one for characters it lacks.
* **Preview:** buttons, fields, a striped table and the status colours in
  the current style.

The theme is kept between sessions. A theme file is TOML with
`format = 1`; anything left out keeps the default, so a lab can share a
short one:

```toml
format = 1
name = "Lab"

[style]
mode = "dark"
corner_radius = 0
density = 0.85

[dark]
accent = "#ffb000"
background = "#101418"
```

The keys are those of the window: `mode`, `zoom`, `corner_radius`,
`window_radius`, `border_width`, `outlined`, `density`, `body_size`,
`monospace_size`, `heading_size`, `small_size`, `text_font`,
`monospace_font` (font file paths; empty for this computer's interface
font, `"builtin"` for egui's), `shadows`, `animations`,
`solid_scrollbars` under `[style]`, and `accent`, `selection`,
`background`, `window`, `input`, `stripe`, `widget`, `hovered`, `border`,
`text`, `good`, `running`, `warn`, `error` (as `"#rrggbb"`) under `[light]`
and `[dark]`.

## Workspaces

**Workspace** in the top bar saves the whole session to a `.ferotrx` file
and opens it again: the servers and which of them were connected, every
port's streams and settings, the profiles being edited in the Stateful,
Applications, Scenario and Benchmark tabs, the multi-server group, the
capture that was open with its ticked packets, the tab on show and the
window's layout (panel sizes, open sections). **New** starts an empty one,
**Save** writes back to the file it came from. Tokens and passwords are
never written; certificates are kept as paths. Opening a workspace connects
to the servers that were connected when it was saved. The file is JSON
(`"format": "ferotrx-workspace-1"`), so it can be kept in version control
next to the profiles it uses.

## The window

| Part | What it does |
| --- | --- |
| **Servers and ports** (left) | Each server with its state, version and backends, and its ports: the interfaces it can send on, plus `file` (a pcap written on the server) and `null` (count and drop), which need no root and are good for trying a profile. ▶ marks a port that is sending. Right-click a server to connect, disconnect, edit or remove it (start and stop, for [This computer](#this-computer)); **Add server…** adds one. |
| **Streams** tab | The selected port: Start, Stop and Check (load on the server without sending), Open…/Save… of profile files on this computer, the port settings, the stream table and the stream editor. |
| **Stateful** tab | Start a TCP or UDP run from a profile, on the server or uploaded from here, with the usual overrides (rate, count, concurrency, duration, workers, backend). **Check** runs `ferotrx check` on a local file. |
| **Applications** tab | Edit TCP and UDP profiles with forms for their application protocols (HTTP, HTTP/2, HTTP/3, DNS, NTP, MQTT, SSH, SIP/RTP, SMB, TLS), check and run them. See [application profiles](#application-profiles). |
| **Capture** tab | Open a pcap or pcapng file on this computer, or capture live on a server's interface with a BPF filter (see [live captures](#live-captures)): packet list, decode tree and hex. Tick packets (or select one) and **Make a stream** to edit them in the Streams tab. **Save…** writes the capture as pcap. |
| **Scenario** tab | Write, check and run [scenarios](#scenarios), read their verdicts and compare two runs. |
| **Benchmark** tab | RFC 2544 benchmarks run by the server, every trial as it ends. See [benchmarks](#benchmarks). |
| **Multi-server** tab | Runs on several servers started and stopped together, with combined counters. See [several servers at once](#several-servers-at-once). |
| **Charts** tab | Packets/s or Mbit/s of every run of the selected server over time, or loss, reordering and latency per flow of what is received. |
| **Statistics** (bottom) | A column per run, a row per counter: stream runs (totals, per stream, loss and latency with a receiver), TCP runs (connections started, established, completed, reset, timed out, retransmits, per template), UDP runs (sent, answered, timed out, retries, response times) and receivers. Stop and remove runs from their column. |
| **Log** (bottom) | What the servers answered, errors in red. |

## Files and paths

Every file field has a **Browse…** button with a file dialog. Files on this
computer (profiles you open and save, captures, certificates) are always
picked this way. Files on the server (the capture a stream replays, the pcap
the `file` port writes, a profile the server reads) can be picked the same
way when the server runs on this computer (`127.0.0.1`, `::1`,
`localhost`, and the server reports this computer's host name and
system); for a server elsewhere, type the path, relative to the
server's data directory (where `ferotrx serve` was started, or
`--data-dir`). A loopback address forwarded into a virtual machine (such
as a VirtualBox NAT port forward to 127.0.0.1:4510) counts as elsewhere.

Relative paths inside a profile start at the profile's own folder, as with
`ferotrx run`: open `examples/lab-two-vlans.toml` and its `pcap = "dns.pcap"`
means `examples/dns.pcap`. The GUI remembers that folder for each port and
sends it with the streams when the server is on this computer (the folder
must be inside the server's data directory). A capture picked with
**Browse…** is written relative to that folder when it is inside it.

The lines between the stream table and the editor, the layers and the
packet view, the decode tree and the bytes, and the capture list and the
packet can all be dragged.

## The lab router

A server started with `--lab` (Linux, as root) can build a router for the
lab examples on its own machine: **Lab router…** under the server opens it.
Servers on Windows and macOS have no lab router, and no entry for it.
The router is in a network namespace, reached on the link `ftrx-lab`, and
routes and masquerades between VLAN 10 (clients, 192.168.10.0/24) and VLAN
20 (servers, 192.168.20.0/24), as the `examples/lab-*.toml` profiles expect;
streams sent to 192.168.20.2 come back on `ftrx-lab`, for "Receive on".
Options add loss, delay, ports the firewall refuses (to see a test fail on
purpose) and DHCP on VLAN 10. Once it runs, the port `ftrx-lab` is selected
and is the interface of the Stateful tab: open `examples/lab-udp-mix.toml`
there and press Start. Details: [lab scripts](lab-scripts.md#a-standing-lab-router).

## Scenarios

The Scenario tab runs [scenarios](scenarios.md): checks with an expected
outcome (`complete`, `blocked`) and conditions on their counters.

* **Prepare it here.** With "from this computer" ticked, the scenario is
  edited in the tab: Open or Browse a file, or New for a small one for the
  lab router; Save writes it back. Check reads it, and every profile it
  names, on this computer, as `ferotrx scenario show` does, and lists the
  checks; untick a check to leave it out of the run.
* **Run it on the server.** "▶ Run on the server" sends the scenario. A
  server on this computer reads the profiles from the scenario's folder; a
  server elsewhere, or one on this computer that may not read that folder
  (the Windows service, with its own data directory), gets them put into
  the scenario (captures they replay are read on the server, from "Server
  folder" or its data directory).
  Without the tick the server reads a scenario file of its own.
* **Read the report.** Each check shows waiting, running with its live
  counters, then ✔, ✘ or ⚠ with its summary. Pick a check for its
  conditions with the values they were judged on, the error if it could not
  run, and all its counters. Save report… writes the JSON report
  (`ferotrx scenario compare` reads it), JUnit… the XML for CI.

`ferotrx-gui --scenario examples/lab-scenario.toml` opens a scenario in the
tab at start. A scenario that names the lab router it needs (`[lab]`, as the
lab scenario does) gets it built by the server before the run (a Linux
server started with `--lab`, as root; on any other server the tab says it
can't build one, and such a scenario only runs there with its interfaces
changed to real ones); untick "Build the lab it names" to run on the lab as
it is, after you changed it in "Lab router…" on purpose.

**Compare…** sets two runs side by side, as `ferotrx scenario compare`
does: pick each side from the scenario runs of any connected server or from
a saved report file (it starts on the run shown and the previous run of the
same scenario). Checks are matched by name and every metric that moved by
more than the tolerance is listed, worse ones in red; with "strict" a
worse metric counts as a regression. Save… writes the comparison as text,
or as JSON when the name ends in `.json`.

## Application profiles

The Applications tab edits the TCP and UDP profiles of the
[application protocols](app-protocols.md) without writing TOML by hand.
New starts a TCP profile (HTTP) or a UDP one (DNS); Open and Browse read one (the
`examples/lab-*.toml` files open as they are). The tree on the left has
the run settings, each template (`[[template]]`; + Template adds one with the
protocol picked, copy duplicates one), the client and server ends, the TCP or UDP options and
the profile text. A template's page picks its protocol from those its
transport carries and shows that protocol's own form: HTTP requests and
routes, HTTP/2 streams, HTTP/3 over QUIC, DNS queries and zones, NTP, MQTT topics, SSH users,
keys and commands, SIP calls with their media, SMB shares and files. "Over
TLS" adds the TLS form ([TLS](app-protocols.md#tls-and-https)): versions,
ciphers, ALPN, SNI, certificates or the generated lab CA, and failures
expected on purpose. Each form shows the profile's value or the engine's
default in grey, checks values as you type, and keeps keys it has no field
for. Check reads the profile as `ferotrx check` does; "▶ Run" starts it on the
selected server, uploaded from here. Comments in the file are lost when a
form rewrites it; the Text page edits the text itself.

## Benchmarks

The Benchmark tab runs [RFC 2544 benchmarks](benchmarking.md) on the
server: throughput (a binary search for the highest load without loss),
latency, frame loss and back-to-back, through a device between two of the
server's interfaces. Pick the profile (edited here, New for a short one
through the lab router, or a file on the server), the interface to send on
and the one to receive on, and optionally other tests, sizes (`rfc2544`,
`imix`, `124 1514`), line rate, trial length, repetitions, workers and
backend than the profile's. "▶ Run on the server" starts it
(`bench.start`); every trial shows as it ends, with a chart of the offered
load of each trial of a size (green without loss, red with), so the search
can be watched closing in. When it ends, the results per size (throughput
in % of the line rate, Mbit/s and frames/s, latency, back-to-back burst,
frame loss) and a throughput chart appear, with the text report. Stop
ends it after the trial under way, with a partial report. Save report…
writes the JSON report and the text report next to it, as
`ferotrx bench --report` does. Throughput in orange means the sender did
not reach the offered rate: it measured the sender, not the device.

## Y.1564

The Y.1564 tab runs [service activation tests](y1564.md) on the server
(`y1564.start`). Pick the profile (edited here, New for two services
through the lab router, or a file on the server), the interface to send on
and the one to receive on, and optionally the tests, services, line rate
and step and performance durations. Each configuration step shows as it
ends, per service: offered rate, information rate, FLR, FTD, FDV, yellow
loss and the verdict with its reasons. The performance test gets a table
per service and charts of loss and delay per interval. Save report…
writes the JSON and text reports, as `ferotrx y1564 --report` does.

## Several servers at once

The Multi-server tab starts runs on several servers together, for traffic
from more than one machine or more than one port of a machine. Each member
is a server, what it runs (a port's streams as built in the Streams tab, or
a TCP or UDP profile) and its own settings; "+ Every connected server"
adds one per server with the streams of the port selected on the left.
**▶ Start all** loads every member's streams first and starts them all only
when every server has accepted them, with a start time one second ahead
in each server's own clock (`start_at`, from the clock offset measured when
it connected), so they begin together; **■ Stop all** stops them together. The table shows each member's
state and counters with a total row, and the chart each member's rate and
their sum over time. The group is saved in the workspace.

## Ports and their settings

A port's streams are sent together, as one profile named `gui-<port>`
(`profile.load`, then `run.start` with the port's output). **Port settings**
holds what `ferotrx run` takes on its command line: backend (`pcap`,
`af_xdp`, `dpdk`, as the server offers them) and AF_XDP mode, workers (see
[several cores](multi-core.md)), a duration, one rate for all streams, an
interface of the same server to receive on (loss and latency per stream, see
[loss and latency](loss-latency.md)), and signatures on all streams for a
receiver on another machine.

## The stream editor

Each stream has four pages:

* **Protocols**: the packets of the stream (`#1`, `#2`, … sent in turn), each
  as its text form (the [packet syntax](packets.md#building-packets)) and as a
  stack of protocol layers. Open a layer to edit its fields; empty fields
  show the builder's default in grey, and lengths and checksums follow the
  layers unless you set them (to send a broken packet on purpose). Values
  are checked as you type (MAC, IPv4, IPv6, ranges of numbers, flag letters).
  **+ Layer** buttons offer what usually comes next; **+ Other layer** has
  every protocol by category, and **+** on a layer inserts after it. The
  text form and the layers stay in step, so either can be edited. The
  **packet view** on the right is the packet as built, decoded again: the
  layer tree with every field, and the hex and ASCII bytes. Select a field
  to see its bytes; click a byte to find its field. **✏ Edit bytes** makes
  the hex view editable: click a byte and type hex digits, move with the
  arrow keys, Home and End, Delete or Backspace removes a byte and Insert
  adds one. Every change is decoded again into layers and fields (lengths
  and checksums left to the builder, as when importing a capture), so the
  layers, the text form and the bytes stay in step; what cannot be carried
  over into fields is listed under the bytes.
* **Stream control**: rate (`1000pps`, `20mbps`, `2x`, `topspeed`) or
  interval, loops (0 is until the run ends), packet limit, start delay,
  traffic model and rate shape ([traffic models](traffic-models.md)), frame
  sizes (`imix`, `rfc2544`, weights), loss and latency signatures.
* **Variable fields**: the field engine (`vary`) and rewrites, as in
  profiles ([replay](replay.md)).
* **Profile text**: the `[[stream]]` table as it goes to the server.

Pages 2 and 3 say whether `ferotrx` reads the stream, using the same parser
as the server, before anything is sent.

A stream can also replay a capture that is on the server (**Replay a
capture instead**), with the capture's timing, a multiple of it, or a rate.

## From a capture to an editable stream

**Make a stream** in the Capture tab turns each picked packet into layers:
Ethernet, VLAN and QinQ tags, ARP, IPv4, IPv6, TCP (with MSS, window scale
and SACK permitted), UDP and ICMP/ICMPv6 echo become fields; what follows
becomes a payload, as text when it is printable (an HTTP request, say) and
as hex otherwise. Lengths and checksums are left to the builder, so a packet
with correct checksums builds back to the same bytes, and stays correct
after you change an address. What cannot be carried over (IPv4 options,
other TCP options, an Ethernet trailer that is not padding) is listed in the
log. The same import is `ferotrx_packet::import` in the library.

## Adding protocols and editors

The GUI is built to grow with the packet builder. Every layer has a
`ProtocolEditor` in `ferotrx_gui::protocols::Registry`: its name and aliases
in the text form, a title, a category (link, network, transport,
application, payload), its fields (`FieldDef`: key, label, kind, default,
help, repeatable), the layers that usually follow it, and the form it draws.
Most editors are a table of fields and use the generic form; the payload
editor draws its own (text, hex or fill).

Application protocols have their own registry in the same `Registry`: an
`AppEditor` names a protocol as profiles do (`app = "mqtt"`, with aliases
such as `https` = HTTP over TLS), the transports that carry it, its default
port, its settings (`Setting`: key, label, kind, default, help), its lists
of tables (`[[http.request]]`) and sub-tables, and an example. Most are a
`TableEditor` with the generic form; `register_app` adds or replaces one,
so a protocol the engine learns gets its form with one call, and the
Applications tab offers it. Tests check every form's keys against the
engine, so a key the engine does not know is caught in CI. A new protocol, such as an
application layer the builder learns, is one more `register` call; a
registered editor with the name of a built-in one replaces it. A layer that
no editor knows still opens, as key and value pairs, so files written for a
newer FeroTRX never lose fields in the GUI.

The other parts are separate from drawing and usable on their own:
`ferotrx_gui::model` (streams, ports and the profiles they become),
`ferotrx_gui::conn` (a worker thread per server that polls the run lists and
takes any control method by name) and the packet import in
`ferotrx-packet`.

## Why egui

The GUI uses [egui](https://github.com/emilk/egui) through eframe: pure
Rust, the same code on Linux, macOS and Windows with no web runtime or
system toolkit to install, quick to draw tables, trees, hex views and
charts that change many times a second, and it builds with the rest of the
workspace (`cargo build`). The control API stays the only way in, so the
GUI can drive a server across the lab as easily as the local one.

## Live captures

The Capture tab's **Live** row captures on an interface of any connected
server (or this computer's): pick the server and the interface, type a BPF
filter (`udp port 53`, `host 10.0.0.1 and not arp`) and press **Start**.
The frames come over the server's control connection and fill the packet
list as they arrive, decoded as for a file; the status line shows frames,
bytes, drops and frames missed when the connection could not keep up.
**Stop** ends it, and the server removes it. A filter that does not compile
shows libpcap's reason in the log.

**Also open Wireshark** starts `wireshark -k -i -` and feeds it the same
frames as pcap, live. Wireshark must be on the PATH (on Windows, add
`C:\Program Files\Wireshark`). The GUI keeps the newest 200000 frames;
**Save…** writes what it holds as pcap. More in [capturing](capture.md).

## Not done yet

* Call quality (jitter, MOS) charts, once the engine measures them (#49).
* Forms keep the profile's values but not its comments.
