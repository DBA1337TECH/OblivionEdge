// Copyright © 1337_TECH, July 2025
// Enhanced L2-L4 packet capture + reassembly engine for Oblivion Edge

mod crypto;
mod patterns;

use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{Write, BufWriter, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::os::unix::fs::OpenOptionsExt;
use libc;
use patterns::{PATTERN_IKEV2, PATTERN_FILEUPLOAD};

/// --- Common Utilities ---

fn now_ts() -> String {
    chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string()
}

fn write_pcap_header(w: &mut BufWriter<File>) {
    w.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1,       // magic number (little-endian)
        0x02, 0x00,                   // version major
        0x04, 0x00,                   // version minor
        0x00, 0x00, 0x00, 0x00,       // thiszone
        0x00, 0x00, 0x00, 0x00,       // sigfigs
        0xff, 0xff, 0x00, 0x00,       // snaplen (max length of captured packets)
        0x65, 0x00, 0x00, 0x00,       // network: LINKTYPE_RAW (101)
    ]).unwrap();
}


fn append_pcap(w: &mut BufWriter<File>, pkt: &[u8]) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let ts_sec  = now.as_secs() as u32;
    let ts_usec = now.subsec_micros();
    let len     = pkt.len() as u32;

    w.write_all(&ts_sec.to_le_bytes()).unwrap();
    w.write_all(&ts_usec.to_le_bytes()).unwrap();
    w.write_all(&len.to_le_bytes()).unwrap();
    w.write_all(&len.to_le_bytes()).unwrap();
    w.write_all(pkt).unwrap();
    w.flush().unwrap();
}

fn read_frame(dev: &mut File) -> Vec<u8> {
    let mut buf = vec![0u8; 4 + 4096];
    let n = loop {
        match dev.read(&mut buf) {
            Ok(n) if n > 0 => break n,
            _ => {
                thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
        }
    };

    if n < 4 { return Vec::new(); }

    let pkt_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    buf[4..4 + pkt_len.min(4096)].to_vec()
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// --- Parsed Packet Struct ---
struct ParsedPacket {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ethertype: u16,
    ip_src: Option<Ipv4Addr>,
    ip_dst: Option<Ipv4Addr>,
    l4_proto: Option<u8>,
    sport: Option<u16>,
    dport: Option<u16>,
    l4_offset: Option<usize>,
    original: Vec<u8>,
}

/// --- Flow Keys and State ---

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    proto: u8,
}

struct TcpFlow {
    packets: Vec<Vec<u8>>,
    next_seq: u32,
    buffer: HashMap<u32, Vec<u8>>,
    reassembled: Vec<u8>,
}

struct UdpFlow {
    packets: Vec<Vec<u8>>,
    last_seen: Instant,
}

/// --- Packet Parsing ---
fn parse_packet(pkt: &[u8]) -> Option<ParsedPacket> {
    if pkt.len() < 14 { return None; }

    let dst_mac = pkt[0..6].try_into().unwrap();
    let src_mac = pkt[6..12].try_into().unwrap();
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);

    if ethertype != 0x0800 || pkt.len() < 34 {
        return Some(ParsedPacket {
            src_mac, dst_mac, ethertype,
            ip_src: None, ip_dst: None,
            l4_proto: None, sport: None, dport: None,
            l4_offset: None, original: pkt.to_vec(),
        });
    }

    let ip = &pkt[14..];
    let ihl = ((ip[0] & 0x0F) * 4) as usize;
    let l4_offset = 14 + ihl;
    if pkt.len() < l4_offset + 4 { return None; }

    let ip_src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let ip_dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let proto = ip[9];

    let (sport, dport) = match proto {
        6 | 17 => (
            Some(u16::from_be_bytes([pkt[l4_offset], pkt[l4_offset + 1]])),
            Some(u16::from_be_bytes([pkt[l4_offset + 2], pkt[l4_offset + 3]])),
        ),
        _ => (None, None),
    };

    Some(ParsedPacket {
        src_mac, dst_mac, ethertype,
        ip_src: Some(ip_src), ip_dst: Some(ip_dst),
        l4_proto: Some(proto), sport, dport,
        l4_offset: Some(l4_offset), original: pkt.to_vec(),
    })
}

fn handle_tcp(flow: &mut TcpFlow, pkt: &[u8], l4_offset: usize) {
    let tcp = &pkt[l4_offset..];
    if tcp.len() < 13 { return; }

    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) * 4) as usize;
    let payload_offset = l4_offset + data_offset;

    if payload_offset >= pkt.len() { return; }

    let data = pkt[payload_offset..].to_vec();

    if flow.reassembled.is_empty() {
        flow.next_seq = seq + data.len() as u32;
        flow.reassembled.extend_from_slice(&data);
        return;
    }

    if seq == flow.next_seq {
        flow.reassembled.extend_from_slice(&data);
        flow.next_seq += data.len() as u32;
        while let Some(buf) = flow.buffer.remove(&flow.next_seq) {
            flow.reassembled.extend_from_slice(&buf);
            flow.next_seq += buf.len() as u32;
        }
    } else {
        flow.buffer.insert(seq, data);
    }
}

fn write_flow_pcap(key: &FlowKey, pkts: &[Vec<u8>], outdir: &PathBuf) {
    let fname = format!(
        "flow_{}_{}_{}_{}_{}_{}.pcap",
        mac_to_string(&key.src_mac),
        mac_to_string(&key.dst_mac),
        key.src_ip, key.sport, key.dst_ip, key.dport
    );
    let path = outdir.join(fname);
    let mut file = BufWriter::new(File::create(path).unwrap());
    write_pcap_header(&mut file);
    for p in pkts {
        append_pcap(&mut file, p);
    }
}

/// --- Capture Loop ---

fn capture_loop(dev_path: &str, proto_name: &str, streams_dir: PathBuf, captured_dir: PathBuf, flows_dir: PathBuf) {
    println!("[{proto_name}] Opening device {dev_path}...");

    let mut dev = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_SYNC)
        .open(dev_path)
        .unwrap();

    let rolling_pcap = streams_dir.join(format!("all_{}_streams.pcap", proto_name.to_lowercase()));
    let mut main_pcap = BufWriter::new(File::create(&rolling_pcap).unwrap());
    write_pcap_header(&mut main_pcap);

    let mut tcp_flows = HashMap::new();
    let mut udp_flows = HashMap::new();

    loop {
        let pkt = read_frame(&mut dev);
        append_pcap(&mut main_pcap, &pkt);

        if let Some(parsed) = parse_packet(&pkt) {
            if let (Some(src_ip), Some(dst_ip), Some(proto), Some(sport), Some(dport), Some(l4)) =
                (parsed.ip_src, parsed.ip_dst, parsed.l4_proto, parsed.sport, parsed.dport, parsed.l4_offset) {

                let flow_key = FlowKey {
                    src_mac: parsed.src_mac,
                    dst_mac: parsed.dst_mac,
                    src_ip,
                    dst_ip,
                    sport,
                    dport,
                    proto,
                };

                match proto {
                    6 => {
                        let flow = tcp_flows.entry(flow_key.clone()).or_insert(TcpFlow {
                            packets: Vec::new(),
                            next_seq: 0,
                            buffer: HashMap::new(),
                            reassembled: Vec::new(),
                        });
                        flow.packets.push(parsed.original.clone());
                        handle_tcp(flow, &parsed.original, l4);
                        if flow.packets.len() >= 50 {
                            write_flow_pcap(&flow_key, &flow.packets, &flows_dir);
                            flow.packets.clear();
                        }
                    }
                    17 => {
                        let len_after = {
                            let flow = udp_flows.entry(flow_key.clone()).or_insert(UdpFlow {
                                packets: Vec::new(),
                                last_seen: Instant::now(),
                            });
                            flow.last_seen = Instant::now();
                            flow.packets.push(parsed.original.clone());
                            flow.packets.len()
                        };
                        udp_flows.retain(|_, f| f.last_seen.elapsed().as_secs() < 30);
                        if len_after >= 20 {
                            if let Some(flow) = udp_flows.get_mut(&flow_key) {
                                write_flow_pcap(&flow_key, &flow.packets, &flows_dir);
                                flow.packets.clear();
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Pattern match system
            let is_ike  = parsed.original.windows(PATTERN_IKEV2.len()).any(|w| w == PATTERN_IKEV2);
            let is_file = parsed.original.windows(PATTERN_FILEUPLOAD.len()).any(|w| w == PATTERN_FILEUPLOAD);

            if is_ike || is_file {
                let ts = now_ts();
                let evt_dir = captured_dir.join(format!("{}_evt_{}", proto_name.to_lowercase(), ts));
                create_dir_all(&evt_dir).unwrap();

                let mut evt_pcap = BufWriter::new(File::create(evt_dir.join("capture.pcap")).unwrap());
                write_pcap_header(&mut evt_pcap);
                append_pcap(&mut evt_pcap, &parsed.original);

                let desc = if is_ike { "IKEv2 suspect" } else { "FileUpload suspect" };
                let metadata = format!(r#"{{"ts":"{}","proto":"{}","match":"{}"}}"#, ts, proto_name, desc);

                std::fs::write(evt_dir.join("metadata.json"), &metadata).unwrap();
                let bundle = [&parsed.original[..], metadata.as_bytes()].concat();
                let enc = crypto::encrypt_and_compress_bundle(&bundle);
                std::fs::write(evt_dir.join("capture.enc.zst"), enc).unwrap();

                println!("[{proto_name}] Suspect event captured → {ts}");
            }
        }
    }
}

/// --- Main: Spawn capture threads ---

fn main() {
    println!("[monitor] Starting full TCP + UDP monitoring engine...");

    let session = now_ts();
    let base = PathBuf::from(format!("output/{session}"));
    let tcp_streams = base.join("tcp_streams");
    let udp_streams = base.join("udp_streams");
    let captured = base.join("captured_patterns");
    let flows_tcp = base.join("flows/tcp");
    let flows_udp = base.join("flows/udp");

    create_dir_all(&tcp_streams).unwrap();
    create_dir_all(&udp_streams).unwrap();
    create_dir_all(&captured).unwrap();
    create_dir_all(&flows_tcp).unwrap();
    create_dir_all(&flows_udp).unwrap();

    let t1 = {
        let captured = captured.clone();
        let flows_tcp = flows_tcp.clone();
        let tcp_streams = tcp_streams.clone();
        thread::spawn(move || {
            capture_loop("/dev/suspect_kmod", "TCP", tcp_streams, captured, flows_tcp);
        })
    };

    let t2 = {
        let captured = captured.clone();
        let flows_udp = flows_udp.clone();
        let udp_streams = udp_streams.clone();
        thread::spawn(move || {
            capture_loop("/dev/suspect_udp_kmod", "UDP", udp_streams, captured, flows_udp);
        })
    };

    t1.join().unwrap();
    t2.join().unwrap();
}
