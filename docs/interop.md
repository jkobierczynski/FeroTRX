# Interoperability

FeroTRX emulates both ends of most protocols itself, and a test where both
ends are FeroTRX proves only that it agrees with itself. This page lists the
other implementations each protocol is tested against, in which direction,
and which lab script does it. Every script here runs in CI on
`ubuntu-latest` (see [ci.md](ci.md)); the tools come from Ubuntu's
packages, installed by the CI step that runs the script. On another machine
a script skips the parts whose tools are missing and says so.

"FeroTRX client" means the emulated client against the real server;
"FeroTRX server" means the real client against the emulated server.

| Protocol | Real implementation | FeroTRX client | FeroTRX server | Script, run |
|---|---|---|---|---|
| TCP (the engine) | Linux kernel stack and its NAT (conntrack, masquerade) on the router; Linux as sender with ECN | through the router | through the router | [tcp-nat-netns.sh](../scripts/tcp-nat-netns.sh) (all runs; `ECN=1` sends from Linux) |
| HTTP/1.1 | curl | | yes | [app-netns.sh](../scripts/app-netns.sh) 2 |
| HTTP/1.1 | Python `http.server` | yes, with response checks | | app-netns.sh 3, [http-netns.sh](../scripts/http-netns.sh) 3 |
| HTTPS (TLS 1.2, 1.3) | curl | | yes | app-netns.sh 5 |
| HTTPS (TLS 1.2 ECDHE_RSA, 1.3) | OpenSSL `s_server` | yes | | app-netns.sh 6 |
| TLS handshakes, resumption | OpenSSL `s_time` (`-new`, `-reuse`) | | yes | [tls-netns.sh](../scripts/tls-netns.sh) 4 |
| TLS handshakes, resumption | OpenSSL `s_server` | yes | | tls-netns.sh 5 |
| HTTP/2 (h2, h2c) | curl `--http2`, `--http2-prior-knowledge`; h2load | | yes | app-netns.sh 11 |
| HTTP/2 (h2, h2c) | nghttpd | yes | | app-netns.sh 12 |
| HTTP/3, QUIC | aioquic (`scripts/h3-peer.py`) | yes, also with Retry | yes | [h3-netns.sh](../scripts/h3-netns.sh) 2, 3 |
| MQTT 3.1.1, 5 | mosquitto_pub, mosquitto_sub | | yes | app-netns.sh 8 |
| MQTT 3.1.1, 5 | mosquitto broker | yes | | app-netns.sh 9 |
| SSH | OpenSSH `ssh` (each cipher, re-key, pty, sshpass) | | yes | app-netns.sh 14 |
| SSH | OpenSSH `sshd` (key login, each cipher, re-key) | yes | | app-netns.sh 15 |
| DNS over UDP | `dig` | | yes | [udp-netns.sh](../scripts/udp-netns.sh) |
| SIP, RTP (digest auth, G.711) | SIPp (built-in caller, a registration scenario) | | yes | [sip-netns.sh](../scripts/sip-netns.sh) 2 |
| SIP, RTP | SIPp (built-in answering end) | yes | | sip-netns.sh 3 |
| SMB 2 and 3 (NTLMv2, signing) | smbclient | | yes | [smb-netns.sh](../scripts/smb-netns.sh) 2 |
| SMB 2 and 3 | Samba `smbd` | yes | | smb-netns.sh 3 |
| DHCPv4, DHCPv6, router advertisements | dnsmasq | yes (host emulation) | | [hosts-netns.sh](../scripts/hosts-netns.sh) 1, 3 and `IPV6=1` |
| DHCPv4, DHCPv6 | busybox `udhcpc`, `udhcpc6` | | yes (DHCP server role) | hosts-netns.sh 4 |
| IGMP, MLD | Linux bridge with snooping and a querier | yes | | hosts-netns.sh 1 |
| Router advertisements, SLAAC | Linux kernel host | | yes (router mode) | hosts-netns.sh `IPV6=1` |
| ARP, neighbor discovery, ping | Linux kernel router | yes (the port's own addresses) | yes (answers) | [link-netns.sh](../scripts/link-netns.sh) 1 and `IPV6=1` |
| pcap files | tcpdump reads what `ferotrx capture` writes | | | [capture-netns.sh](../scripts/capture-netns.sh) |

Not tested against another implementation yet: DNS over TCP and over TLS
(both ends FeroTRX in app-netns.sh 1 and 4), NTP (both ends FeroTRX in
udp-netns.sh `MIX=1`), RTCP reports to and from SIPp (only RTP is echoed),
DHCPv6 prefix delegation (not implemented). Benchmarks (RFC 2544) and
Y.1564 are measured against the Linux kernel's own shapers and policers
(tc `tbf`, `police`, `htb`) in [bench-netns.sh](../scripts/bench-netns.sh)
and [y1564-netns.sh](../scripts/y1564-netns.sh).
