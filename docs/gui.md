# The desktop GUI

`ferotrx-gui` is a window onto one or more FeroTRX control servers
(`ferotrx serve`), on this machine or elsewhere in the lab. It shows each
server's interfaces as ports, lets you build streams for a port layer by
layer with a live packet view, sends them, starts stateful TCP and UDP runs,
and shows every run's counters in a grid and in rate charts. It is another
client of the [control API](remote-control.md), like `ferotrx ctl` and the
[Python client](python-client.md): whatever it sends is an ordinary profile
that `ferotrx run` sends the same way.

It runs on Linux (X11 and Wayland), macOS and Windows. It needs no
privileges itself; the server does the sending.

```sh
cargo build --release -p ferotrx-gui         # target/release/ferotrx-gui

sudo ferotrx serve &                         # a server on 127.0.0.1:4510
ferotrx-gui                                  # connects to it

# A server elsewhere, over TLS with a client certificate (see remote-control.md):
ferotrx-gui --connect 192.168.56.10 --ca ca.pem --cert alice.pem --key alice-key.pem

# Open on a port with a profile's streams, or with a capture:
ferotrx-gui --port enp0s3 --profile examples/lab-two-vlans.toml
ferotrx-gui examples/web.pcap
```

`FEROTRX_CTL`, `FEROTRX_CA`, `FEROTRX_CERT`, `FEROTRX_KEY` and
`FEROTRX_TOKEN` work as for `ferotrx ctl`. Tokens are never saved; the rest
(servers, every port's streams and settings, the last port open) is kept
between sessions.

## The window

| Part | What it does |
| --- | --- |
| **Servers and ports** (left) | Each server with its state, version and backends, and its ports: the interfaces it can send on, plus `file` (a pcap written on the server) and `null` (count and drop), which need no root and are good for trying a profile. ▶ marks a port that is sending. Right-click a server to connect, disconnect, edit or remove it; **Add server…** adds one. |
| **Streams** tab | The selected port: Start, Stop and Check (load on the server without sending), Open…/Save… of profile files on this computer, the port settings, the stream table and the stream editor. |
| **Stateful** tab | Start a TCP or UDP run from a profile, on the server or uploaded from here, with the usual overrides (rate, count, concurrency, duration, workers, backend). **Check** runs `ferotrx check` on a local file. |
| **Capture** tab | Open a pcap or pcapng file on this computer: packet list, decode tree and hex. Tick packets (or select one) and **Make a stream** to edit them in the Streams tab. |
| **Charts** tab | Packets/s or Mbit/s of every run of the selected server over time. |
| **Statistics** (bottom) | A column per run, a row per counter: stream runs (totals, per stream, loss and latency with a receiver), TCP runs (connections started, established, completed, reset, timed out, retransmits, per template), UDP runs (sent, answered, timed out, retries, response times) and receivers. Stop and remove runs from their column. |
| **Log** (bottom) | What the servers answered, errors in red. |

## Files and paths

Every file field has a **Browse…** button with a file dialog. Files on this
computer (profiles you open and save, captures, certificates) are always
picked this way. Files on the server (the capture a stream replays, the pcap
the `file` port writes, a profile the server reads) can be picked the same
way when the server runs on this computer (`127.0.0.1`, `::1`,
`localhost`); for a server elsewhere, type the path, relative to the
server's data directory (where `ferotrx serve` was started, or
`--data-dir`).

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
The router is in a network namespace, reached on the link `ftrx-lab`, and
routes and masquerades between VLAN 10 (clients, 192.168.10.0/24) and VLAN
20 (servers, 192.168.20.0/24), as the `examples/lab-*.toml` profiles expect.
Options add loss, delay, ports the firewall refuses (to see a test fail on
purpose) and DHCP on VLAN 10. Once it runs, the port `ftrx-lab` is selected
and is the interface of the Stateful tab: open `examples/lab-udp-mix.toml`
there and press Start. Details: [lab scripts](lab-scripts.md#a-standing-lab-router).

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
  to see its bytes; click a byte to find its field.
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
editor draws its own (text, hex or fill). A new protocol, such as an
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

## Not done yet

* Saving and opening whole workspaces (all ports and servers) as a file.
* Editing the bytes of a packet in the hex view directly.
* Charts of receive-side loss and latency over time.
* Starting scenarios and benchmarks from the GUI (`ferotrx scenario`,
  `ferotrx bench` on the command line).
* Several servers' runs started together (distributed agents, issue #21).
