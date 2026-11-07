# Capturing traffic

FeroTRX captures on its own interfaces with BPF filters (the filters
tcpdump and Wireshark's capture filters take). It shows the frames decoded,
writes them as pcap (to a file, a ring of files, or standard output for
Wireshark) and does the same on a remote control server or on every agent
of a [fleet](fleet.md). Captures go through libpcap on Linux and macOS and
Npcap on Windows, so they need the same rights as sending
([installing](install.md)).

## On this machine

```sh
ferotrx capture -i eth0 udp port 53                # decoded, until Ctrl-C
ferotrx capture -i eth0 -f 'host 10.0.0.1 and not arp' -c 100 -v
ferotrx capture -i eth0 -w dns.pcap -d 30s udp port 53
ferotrx capture -i eth0 -w ring.pcap --rotate 100M --files 10   # ring-00001.pcap, ...
ferotrx capture -i eth0 --direction in -x icmp     # only received frames, with hex
```

The filter goes with `-f` or after the options, unquoted, as tcpdump takes
it. A filter that does not compile is refused before anything starts, with
libpcap's reason. Other options: `-s` (bytes kept of each frame, default
262144), `--no-promisc`, `--buffer MiB` (the kernel's capture buffer,
default 32), `--print` (show frames while writing them), `-q`.

`--rotate` takes a size (`512k`, `100M`, `1G`) or a time (`30s`, `5m`);
`--files N` keeps only the newest N files. FeroTRX leaves its own control traffic out of every capture: TCP on the
control port (4510; `--ctl-port` for a `ferotrx serve` on another port) is
added to the filter as `and not tcp port 4510`. `--ctl-traffic` keeps it.
On Linux, time stamps are in
nanoseconds (the pcap files use the nanosecond magic, which Wireshark and
tcpdump read). Npcap cannot choose a direction, so `--direction` is refused
on Windows.

At the end the command prints what it took and what libpcap counted:
frames received by the filter, dropped for lack of buffer room, and dropped
by the interface.

## Into Wireshark

`-w -` writes pcap to standard output and flushes it as frames come, so
Wireshark shows them live. Lines that would go to standard output go to
standard error.

```sh
ferotrx capture -i eth0 -w - udp | wireshark -k -i -
ferotrx capture -i eth0 -w - --print tcp port 80 | tshark -r -    # also see them here
```

On Windows (PowerShell or cmd), Wireshark's folder is usually not on the
PATH:

```bat
ferotrx capture -i Ethernet -w - udp | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -
```

When Wireshark closes, the capture ends (a broken pipe is a normal end).

## Filtering a file

`ferotrx inspect` takes the same filters, so a file can be cut down without
Wireshark:

```sh
ferotrx inspect big.pcap -f 'tcp port 443 and host 10.0.0.5'
```

Packet numbers stay those of the file, and the summary says how many matched.

## Next to a run

`replay`, `run`, `tcp`, `udp` and `host` take `--capture FILE`: a capture on
the run's interface (both directions) for as long as the run goes, so one
command gives the traffic and the pcap of it. `--capture-iface` captures on
another interface (the far side of a device under test), and
`--capture-filter` takes a BPF filter.

```sh
ferotrx tcp lab-tcp.toml -i enp0s8 --capture run.pcap --capture-filter 'tcp port 80'
ferotrx replay web.pcap -i eth1 --capture far.pcap --capture-iface eth2
```

Frames that AF_XDP or DPDK send skip the kernel's taps, so they are not in
such a capture; the frames received on a pcap or AF_XDP port still are.
Capture them on the far side (`--capture-iface`) instead.

## On a remote server

A control server ([remote control](remote-control.md)) captures on its own
interfaces for a client elsewhere. `ferotrx ctl capture` takes the same
options as `ferotrx capture`; the frames come over the control connection
(TLS where the server has it) and are shown, written or piped here:

```sh
ferotrx ctl -c lab:4510 capture -i enp0s8 -w - udp | wireshark -k -i -
ferotrx ctl -c lab:4510 capture -i enp0s8 -w here.pcap -d 1m tcp port 80
ferotrx ctl -c lab:4510 capture -i enp0s8 --save caps/web.pcap tcp port 80   # a copy stays on the server
```

The server leaves its own control connections out (TCP on the port it
listens on), so the capture does not capture itself being read;
`--ctl-traffic` keeps them. The server keeps up to 20000 frames (32 MiB) for a client that reads them.
A client that falls behind (a slow link) loses the oldest, and the summary
says how many it missed; the server's copy (`--save`) has them all. The
capture ends with Ctrl-C, `-c` or `-d`, and is removed from the server. If
the client goes away instead, a capture without a file stops on its own
once no client has read it for a minute.

A long capture can run on the server without a client, into files in its
data directory, and be fetched later:

```sh
ferotrx ctl -c lab:4510 capture-start -i enp0s8 -w caps/night.pcap --rotate 1G --files 8 tcp
ferotrx ctl -c lab:4510 captures
ferotrx ctl -c lab:4510 capture-stop 3
ferotrx ctl -c lab:4510 fetch caps/night-00008.pcap      # checked by SHA-256
ferotrx ctl -c lab:4510 fetch report.json -o - | jq .
```

Capture files stay inside the server's data directories, like everything
else it writes. A read-only login may list captures but not start, read or
stop them.

Over plain SSH, without a control server, the pipe works the same way:

```sh
ssh lab sudo ferotrx capture -i enp0s8 -w - udp | wireshark -k -i -
```

## On every agent of a fleet

A [fleet plan](fleet.md#captures) lists captures with `[[capture]]`.
`ferotrx fleet run --collect DIR` fetches one pcap per agent and interface
after the run, and `--merge FILE` merges them into one pcapng. Each agent's
interface becomes its own interface in the pcapng (`east:d0`), and the
times are moved onto the controller's clock with the offsets the
controller measured, so the frames line up.

## In the GUI

The Capture tab has a **Live** row: a server (this computer or one you
connected), an interface, a BPF filter and **Start**. Frames fill the
packet list as they come, decoded as for a file. **Wireshark** also
starts `wireshark -k -i -` and feeds it the same frames. **Control
traffic** keeps the server's own control connections, which are left out
otherwise. **Save…** writes
what was captured as pcap. See [the GUI](gui.md#live-captures).

## From programs

The control protocol has `capture.start`, `capture.read`, `capture.get`,
`capture.list`, `capture.stop`, `capture.remove` and `file.get`
([the methods](remote-control.md#the-protocol)). `capture.read` long-polls:
it returns the frames after the number given (base64, nanosecond time
stamps, numbered from 1), waiting up to `wait_ms` (at most 2000) for the
first. Its `missed` tells how many had left the server's buffer.

In Python ([the Python client](python-client.md#captures-and-files)):

```python
cap = c.capture_start("enp0s8", filter="udp port 53")
with open("dns.pcap", "wb") as f:
    c.capture_pcap(cap.id, f)        # until the capture ends
```

In Rust: `ferotrx_io::LiveCapture` (a `ferotrx_core::live::FrameSource`),
`ferotrx_core::live::CaptureJob`, the writers `PcapStreamWriter`,
`PcapngWriter` and `CaptureFiles`, and `ferotrx_io::FrameFilter` for
filtering frames already captured.

## Lab script

`scripts/capture-netns.sh` checks all of this between two namespaces:
a filter against what tcpdump reads back, `-w -` into tcpdump, a ring of
files, `--direction in`, a capture on a server in the other namespace read
over ctl and fetched, `--capture` next to a run, and `inspect -f`. CI runs
it, and `scripts/fleet-netns.sh` collects and merges captures from two
agents.

```sh
sudo scripts/capture-netns.sh
```

## Not done

* Frames that AF_XDP or DPDK send are not copied into captures; capture
  them on the far side.
* A fleet's captures are collected after the run; there is no live, merged
  feed from every agent at once.
