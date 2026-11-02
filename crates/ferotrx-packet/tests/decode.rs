use std::path::Path;
use std::time::Duration;

use ferotrx_core::{Capture, Packet, Rewrite, Transform};
use ferotrx_packet::{decode, hex_dump, Decoded, LINKTYPE_ETHERNET, LINKTYPE_RAW};

fn sample(name: &str) -> Capture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    Capture::from_path(path).unwrap()
}

fn rewrite(spec: &str, data: &[u8]) -> Vec<u8> {
    let mut r: Rewrite = spec.parse().unwrap();
    let mut p = Packet::new(Duration::ZERO, data.to_vec());
    r.apply(&mut p);
    p.data
}

fn protocols(d: &Decoded) -> Vec<&str> {
    d.layers.iter().map(|l| l.protocol).collect()
}

#[test]
fn dns_query() {
    let cap = sample("dns.pcap");
    let d = decode(cap.linktype, &cap.packets[0].data);
    assert_eq!(protocols(&d), ["Ethernet", "IPv4", "UDP", "DNS"]);
    assert_eq!(d.protocol, "DNS");
    assert_eq!(d.info, "Standard query 0x1000 A example.com");
    assert_eq!(
        (d.source.as_str(), d.destination.as_str()),
        ("10.1.2.10", "10.1.2.1")
    );
    assert!(d.problems.is_empty(), "{:?}", d.problems);
    let udp = d.layer("UDP").unwrap();
    assert!(udp
        .fields
        .iter()
        .any(|f| f.name == "Checksum" && f.value.ends_with("[correct]")));
}

#[test]
fn tcp_handshake_and_http() {
    let cap = sample("web.pcap");
    let syn = decode(cap.linktype, &cap.packets[0].data);
    assert_eq!(syn.protocol, "TCP");
    assert!(
        syn.info.starts_with("50000 → 80 [SYN] Seq=1000"),
        "{}",
        syn.info
    );
    let get = decode(cap.linktype, &cap.packets[2].data);
    assert_eq!(get.protocol, "HTTP");
    assert_eq!(get.info, "GET /page0.html HTTP/1.1");
    assert!(get.problems.is_empty(), "{:?}", get.problems);
}

#[test]
fn rewrites_show_up_in_the_decode() {
    let cap = sample("dns.pcap");
    let tagged = rewrite("vlan_push=10:3", &cap.packets[0].data);
    let moved = rewrite("ip_dst=192.168.20.50", &tagged);
    let d = decode(LINKTYPE_ETHERNET, &moved);
    assert_eq!(protocols(&d), ["Ethernet", "VLAN", "IPv4", "UDP", "DNS"]);
    assert!(d
        .layer("VLAN")
        .unwrap()
        .title
        .contains("PRI: 3, DEI: 0, ID: 10"));
    assert_eq!(d.destination, "192.168.20.50");
    assert!(d.problems.is_empty(), "{:?}", d.problems);
}

#[test]
fn bad_checksums_are_reported() {
    let cap = sample("dns.pcap");
    let mut p = cap.packets[0].data.clone();
    p[24] ^= 0xff; // IPv4 header checksum
    p[40] ^= 0xff; // UDP checksum
    let d = decode(LINKTYPE_ETHERNET, &p);
    assert_eq!(d.problems.len(), 2, "{:?}", d.problems);
}

#[test]
fn padding_after_short_ip_datagram() {
    // ARP-sized TCP ACK padded to the 60 byte Ethernet minimum.
    let cap = sample("web.pcap");
    let mut p = cap.packets[1].data.clone();
    p.resize(60, 0);
    let d = decode(LINKTYPE_ETHERNET, &p);
    assert_eq!(protocols(&d), ["Ethernet", "IPv4", "TCP", "Padding"]);
}

#[test]
fn ipv6_icmpv6_echo() {
    let mut p = vec![
        0x33, 0x33, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 1, 0x86, 0xdd, // eth
        0x60, 0, 0, 0, 0, 8, 58, 64, // ipv6, payload 8, icmpv6
    ];
    p.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    p.extend([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    p.extend([128, 0, 0, 0, 0x12, 0x34, 0, 7]);
    let p = rewrite("fix_checksums", &p);
    let d = decode(LINKTYPE_ETHERNET, &p);
    assert_eq!(protocols(&d), ["Ethernet", "IPv6", "ICMPv6"]);
    assert_eq!(d.info, "Echo (ping) request id=0x1234 seq=7");
    assert_eq!(
        (d.source.as_str(), d.destination.as_str()),
        ("fe80::1", "ff02::1")
    );
    assert!(d.problems.is_empty(), "{:?}", d.problems);
    assert!(d.layer("Ethernet").unwrap().fields[0]
        .value
        .ends_with("(multicast)"));

    // Same packet as raw IP.
    let raw = decode(LINKTYPE_RAW, &p[14..]);
    assert_eq!(raw.protocol, "ICMPv6");
}

#[test]
fn dns_response_with_compression() {
    let mut msg = vec![
        0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, // header: response, 1 q, 2 an
        3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        0, 1, 0, 1, // A IN
        0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 16, // CNAME -> example.com
        0xc0, 16, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34, // A
    ];
    let mut udp = vec![0, 53, 0x9c, 0x40];
    udp.extend(((msg.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.append(&mut msg);
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 10, 0, 0, 5,
    ];
    let total = (ip.len() + udp.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend(udp);
    let p = rewrite(
        "fix_checksums",
        &[&[0u8; 12][..], &[0x08, 0x00], &ip].concat(),
    );
    let d = decode(LINKTYPE_ETHERNET, &p);
    assert_eq!(
        d.info,
        "Standard query response 0xabcd A www.example.com CNAME example.com A 93.184.216.34"
    );
    assert!(d.problems.is_empty(), "{:?}", d.problems);
}

#[test]
fn arp_reply() {
    let mut p = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06];
    p.extend([0, 1, 0x08, 0, 6, 4, 0, 2]);
    p.extend([0x02, 0, 0, 0, 0, 1, 192, 168, 1, 1]);
    p.extend([0x02, 0, 0, 0, 0, 2, 192, 168, 1, 10]);
    p.resize(60, 0);
    let d = decode(LINKTYPE_ETHERNET, &p);
    assert_eq!(d.info, "192.168.1.1 is at 02:00:00:00:00:01");
    assert_eq!(protocols(&d), ["Ethernet", "ARP", "Padding"]);
}

#[test]
fn never_panics_on_truncated_or_random_input() {
    let mut packets: Vec<Vec<u8>> = sample("dns.pcap")
        .packets
        .into_iter()
        .map(|p| p.data)
        .collect();
    packets.extend(sample("web.pcap").packets.into_iter().map(|p| p.data));
    for p in &packets {
        for n in 0..=p.len() {
            for lt in [1, 101, 113, 228, 229] {
                let _ = decode(lt, &p[..n]);
            }
        }
    }
    // Random bytes behind valid looking headers.
    let mut x: u64 = 0x1234_5678;
    for _ in 0..20_000 {
        let mut p = packets[(x % packets.len() as u64) as usize].clone();
        for _ in 0..4 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = (x as usize) % p.len();
            p[i] = (x >> 32) as u8;
        }
        let d = decode(1, &p);
        let _ = d.tree();
    }
}

#[test]
fn tree_and_hex_dump_render() {
    let cap = sample("dns.pcap");
    let d = decode(cap.linktype, &cap.packets[0].data);
    let tree = d.tree();
    assert!(
        tree.starts_with("Ethernet II, Src: 02:00:00:00:0a:01, Dst: 02:00:00:00:00:01  [0..14]")
    );
    assert!(tree.contains("    Query 1: example.com A  ["));
    assert_eq!(
        hex_dump(&cap.packets[0].data).lines().count(),
        cap.packets[0].data.len().div_ceil(16)
    );
}

/// The builder's checksums agree with the core library's independent
/// checksum code: `fix_checksums` leaves every built packet unchanged.
#[test]
fn built_packets_survive_fix_checksums() {
    let specs = [
        "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1000,dport=2000)/raw(text=\"odd\")",
        "eth/vlan(id=10)/ipv4/tcp(flags=PA,seq=99,ack=7,mss=1400)/raw(len=33,fill=0x5a)",
        "eth/qinq(id=100)/vlan(id=20)/ipv6(src=2001:db8::a,dst=2001:db8::b)/udp/dns(q=x.example)",
        "eth/ipv6/icmp(id=7,seq=3)/raw(hex=0102030405)",
        "eth/ipv6/tcp(sport=5,dport=6,flags=S)",
        "ipv4/udp/dns(qr=1,q=example.com,a=192.0.2.80)",
    ];
    for text in specs {
        let spec: ferotrx_packet::PacketSpec = text.parse().unwrap();
        let data = spec.build().unwrap();
        let d = decode(spec.linktype().unwrap(), &data);
        assert!(d.problems.is_empty(), "{text}: {:?}", d.problems);
        if spec.linktype().unwrap() == LINKTYPE_ETHERNET {
            assert_eq!(rewrite("fix_checksums", &data), data, "{text}");
        } else {
            assert_eq!(d.protocol, "DNS");
            assert_eq!(spec.linktype().unwrap(), LINKTYPE_RAW);
        }
    }
}
