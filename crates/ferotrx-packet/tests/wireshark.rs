//! Built packets checked against Wireshark: every tunnel and multicast
//! header is dissected by tshark and its fields compared with what was asked
//! for, with checksum validation on.
//!
//! Skipped when tshark is not installed, unless FEROTRX_REQUIRE_TSHARK=1
//! (CI sets it).

use std::io::Write;
use std::process::Command;

use ferotrx_packet::{decode, PacketSpec};

/// A packet, tshark options it needs, and `field=value` pairs tshark must show.
struct Case {
    spec: &'static str,
    opts: &'static [&'static str],
    want: &'static [(&'static str, &'static str)],
}

const CASES: &[Case] = &[
    Case {
        spec: "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp/vxlan(vni=5000)/eth/ipv4(src=192.168.1.1,dst=192.168.1.2)/udp(sport=1000,dport=2000)/raw(len=10)",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ip:udp:vxlan:eth:ethertype:ip:udp:data"),
            ("vxlan.vni", "5000"),
            ("ip.dst", "10.0.0.2,192.168.1.2"),
            ("udp.checksum.status", "1,1"),
            ("ip.checksum.status", "1,1"),
        ],
    },
    Case {
        spec: "eth/ipv6/udp/geneve(vni=7,opt=01020300)/eth/ipv6/icmp",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ipv6:udp:geneve:eth:ethertype:ipv6:icmpv6"),
            ("geneve.vni", "0x000007"),
            ("udp.checksum.status", "1"),
            ("icmpv6.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv4/udp/geneve(vni=9)/ipv4/tcp(flags=S)",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ip:udp:geneve:ip:tcp"),
            ("geneve.vni", "0x000009"),
            ("tcp.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv4(src=10.1.0.1,dst=10.2.0.1)/udp/gtpu(teid=0x1234,qfi=9,pdu=ul,seq=7)/ipv4(src=172.16.0.5,dst=8.8.8.8)/udp/dns(q=example.com)",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ip:udp:gtp:ip:udp:dns"),
            ("gtp.teid", "0x00001234"),
            ("gtp.seq_number", "0x0007"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "9"),
            ("gtp.ext_hdr.pdu_ses_con.pdu_type", "1"),
            ("udp.checksum.status", "1,1"),
        ],
    },
    Case {
        spec: "eth/ipv6/udp/gtpu(teid=99)/ipv6/icmp",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ipv6:udp:gtp:ipv6:icmpv6"),
            ("gtp.teid", "0x00000063"),
            ("gtp.message", "0xff"),
        ],
    },
    Case {
        spec: "eth/ipv4/gre(key=42,seq=3,csum=1)/eth/ipv4/icmp",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ip:gre:eth:ethertype:ip:icmp"),
            ("gre.key", "0x0000002a"),
            ("gre.sequence_number", "3"),
            ("gre.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv6/gre/ipv4/udp/raw(len=4)",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:ethertype:ipv6:gre:ip:udp:discard"),
            ("gre.proto", "0x0800"),
            ("udp.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/vlan(id=5)/mpls(label=100,tc=5)/mpls(label=200,ttl=1)/ipv4/udp/raw(len=4)",
        opts: &[],
        want: &[
            // Not frame.protocols: Wireshark 4.4 leaves `ip` out of it after
            // MPLS (4.2 has it), though it dissects the IPv4 header.
            ("vlan.id", "5"),
            ("ip.version", "4"),
            ("ip.checksum.status", "1"),
            ("udp.checksum.status", "1"),
            ("mpls.label", "100,200"),
            ("mpls.exp", "5,0"),
            ("mpls.bottom", "0,1"),
            ("mpls.ttl", "64,1"),
        ],
    },
    Case {
        // Wireshark guesses whether an Ethernet pseudowire has a control
        // word; tell it, as one does for a known label.
        spec: "eth/mpls(label=17)/eth(src=02:00:00:00:00:01)/ipv4/icmp",
        opts: &["-d", "mpls.label==17,pwethcw"],
        want: &[
            ("eth.src", "02:00:00:00:00:fe,02:00:00:00:00:01"),
            ("icmp.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/llc/snap/ipv4/udp/raw(len=4)",
        opts: &[],
        want: &[
            ("frame.protocols", "eth:llc:ip:udp:discard"),
            ("llc.oui", "0"),
            ("llc.type", "0x0800"),
        ],
    },
    Case {
        spec: "eth(dst=01:80:c2:00:00:00)/llc(dsap=0x42,ssap=0x42)/raw(hex=000000000080000000000000000000000080000000000000008001000014000200000f00)",
        opts: &[],
        want: &[("frame.protocols", "eth:llc:stp"), ("llc.dsap", "0x42")],
    },
    Case {
        spec: "eth/ipv4/ipv4/icmp",
        opts: &[],
        want: &[("frame.protocols", "eth:ethertype:ip:ip:icmp"), ("ip.checksum.status", "1,1")],
    },
    Case {
        spec: "eth/ipv4/ipv6/icmp",
        opts: &[],
        want: &[("frame.protocols", "eth:ethertype:ip:ipv6:icmpv6"), ("icmpv6.checksum.status", "1")],
    },
    Case {
        spec: "eth/ipv6/ipv4/icmp",
        opts: &[],
        want: &[("frame.protocols", "eth:ethertype:ipv6:ip:icmp")],
    },
    Case {
        spec: "eth/ipv4(dst=224.0.0.22,ttl=1)/igmp(rec=join@239.1.2.3,rec=allow@232.1.1.1+10.0.0.9)",
        opts: &[],
        want: &[
            ("igmp.type", "0x22"),
            ("igmp.num_grp_recs", "2"),
            ("igmp.record_type", "4,5"),
            ("igmp.maddr", "239.1.2.3,232.1.1.1"),
            ("igmp.saddr", "10.0.0.9"),
            ("igmp.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv4/igmp(type=v3query,group=239.1.1.1,src=10.0.0.1,src=10.0.0.2)",
        opts: &[],
        want: &[
            ("igmp.type", "0x11"),
            ("igmp.version", "3"),
            ("igmp.num_src", "2"),
            ("igmp.qrv", "2"),
            ("igmp.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv4/igmp(type=query,group=0.0.0.0)",
        opts: &[],
        want: &[("igmp.type", "0x11"), ("igmp.version", "2"), ("igmp.max_resp", "100")],
    },
    Case {
        spec: "eth/ipv4/igmp(type=leave,group=239.9.9.9)",
        opts: &[],
        want: &[("igmp.type", "0x17"), ("igmp.maddr", "239.9.9.9")],
    },
    Case {
        spec: "eth/ipv6(hlim=1,dst=ff02::16)/hbh(ra=0)/mld(rec=join@ff3e::1234,rec=block@ff3e::1+2001:db8::1)",
        opts: &[],
        want: &[
            ("icmpv6.type", "143"),
            ("icmpv6.mldr.nb_mcast_records", "2"),
            ("icmpv6.mldr.mar.record_type", "4,6"),
            ("icmpv6.mldr.mar.multicast_address", "ff3e::1234,ff3e::1"),
            ("icmpv6.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv6/hbh(ra=0)/mld(type=v2query,group=ff3e::1,src=2001:db8::5)",
        opts: &[],
        want: &[
            ("icmpv6.type", "130"),
            ("icmpv6.mld.multicast_address", "ff3e::1"),
            ("icmpv6.mld.nb_sources", "1"),
            ("icmpv6.checksum.status", "1"),
        ],
    },
    Case {
        spec: "eth/ipv6/hbh(ra=0)/mld(type=done,group=ff3e::1)",
        opts: &[],
        want: &[("icmpv6.type", "132"), ("icmpv6.checksum.status", "1")],
    },
];

fn tshark() -> bool {
    let found = Command::new("tshark")
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success());
    if !found && std::env::var("FEROTRX_REQUIRE_TSHARK").as_deref() == Ok("1") {
        panic!("tshark is not installed, and FEROTRX_REQUIRE_TSHARK=1");
    }
    found
}

fn pcap(frame: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(0xa1b2c3d4u32.to_le_bytes());
    f.extend(2u16.to_le_bytes());
    f.extend(4u16.to_le_bytes());
    f.extend([0u8; 8]);
    f.extend(65535u32.to_le_bytes());
    f.extend(1u32.to_le_bytes());
    f.extend([0u8; 8]);
    f.extend((frame.len() as u32).to_le_bytes());
    f.extend((frame.len() as u32).to_le_bytes());
    f.extend(frame);
    f
}

#[test]
fn tshark_dissects_what_was_built() {
    if !tshark() {
        eprintln!("tshark not found: skipped");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ferotrx-ws-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut failures = Vec::new();
    for (n, case) in CASES.iter().enumerate() {
        let spec: PacketSpec = case.spec.parse().unwrap();
        let frame = spec.build().unwrap();
        let ours = decode(spec.linktype().unwrap(), &frame);
        assert!(
            ours.problems.is_empty(),
            "{}: {:?}",
            case.spec,
            ours.problems
        );
        let path = dir.join(format!("{n}.pcap"));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&pcap(&frame))
            .unwrap();
        let mut cmd = Command::new("tshark");
        cmd.arg("-r").arg(&path);
        for p in ["ip", "udp", "tcp"] {
            cmd.args(["-o", &format!("{p}.check_checksum:TRUE")]);
        }
        cmd.args(case.opts);
        cmd.args([
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]);
        for (f, _) in case.want {
            cmd.args(["-e", f]);
        }
        cmd.args(["-e", "_ws.malformed", "-e", "_ws.expert.severity"]);
        let out = cmd.output().expect("tshark runs");
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next().unwrap_or_default();
        let got: Vec<&str> = line.split('|').collect();
        for (i, (f, want)) in case.want.iter().enumerate() {
            let g = got.get(i).copied().unwrap_or_default();
            if g != *want {
                failures.push(format!("{}: {f} is '{g}', wanted '{want}'", case.spec));
            }
        }
        let malformed = got.get(case.want.len()).copied().unwrap_or_default();
        // Expert severities: 0x00400000 warning, 0x00800000 error.
        let severe = got
            .get(case.want.len() + 1)
            .copied()
            .unwrap_or_default()
            .split(',')
            .any(|s| matches!(s, "0x00400000" | "0x00800000" | "4194304" | "8388608"));
        if !malformed.is_empty() || severe {
            failures.push(format!("{}: tshark warns: {line}", case.spec));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
