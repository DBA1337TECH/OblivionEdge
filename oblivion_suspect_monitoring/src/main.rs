// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.

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


/// ----------- SHARED HELPERS ---------------------------------------------------

fn now_ts() -> String {
    let now = chrono::Utc::now();
    now.format("%Y%m%d_%H%M%S").to_string()
}

fn write_pcap_header(w: &mut BufWriter<File>) {
    w.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
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
    // Maximum needed: 4 bytes length + up to MAX_PKT_SIZE
    let mut buf = vec![0u8; 4 + 4096];

    let n = loop {
        match dev.read(&mut buf) {
            Ok(n) if n > 0 => break n,
            Ok(0) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Ok(_) => {
                // Must handle this for Rust exhaustiveness
                continue;
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
        }
    };

    if n < 4 {
        // impossible unless device misbehaves
        return Vec::new();
    }

    let pkt_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;

    if pkt_len > 4096 {
        // unexpected, clamp it
        return buf[4..4 + 4096].to_vec();
    }

    buf[4..4 + pkt_len].to_vec()
}



/// ----------- FLOW STRUCTURES ---------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    proto: u8, // 6=TCP, 17=UDP
}

struct TcpFlow {
    packets: Vec<Vec<u8>>,             // raw packet list
    next_seq: u32,                     // reassembly expected sequence
    buffer: HashMap<u32, Vec<u8>>,     // out-of-order segments
    reassembled: Vec<u8>,              // reassembled payload
}

struct UdpFlow {
    packets: Vec<Vec<u8>>,
    last_seen: Instant,
}

/// Extract flow key + L4 header offset
fn parse_flow(pkt: &[u8]) -> Option<(FlowKey, usize)> {
    if pkt.len() < 34 { return None; }

    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 { return None; }

    let ip = &pkt[14..];
    let proto = ip[9];

    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let ihl = (ip[0] & 0x0F) as usize * 4;
    let l4 = 14 + ihl;

    if pkt.len() < l4 + 4 { return None; }

    let sport = u16::from_be_bytes([pkt[l4], pkt[l4+1]]);
    let dport = u16::from_be_bytes([pkt[l4+2], pkt[l4+3]]);

    Some((FlowKey { src, dst, sport, dport, proto }, l4))
}

/// TCP reassembly logic
fn handle_tcp(flow: &mut TcpFlow, pkt: &[u8], l4_offset: usize) {
    let tcp = &pkt[l4_offset..];

    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) * 4) as usize;
    let payload_offset = l4_offset + data_offset;

    if payload_offset >= pkt.len() { return; }

    let data = pkt[payload_offset..].to_vec();

    // First packet in flow
    if flow.reassembled.is_empty() {
        flow.next_seq = seq + data.len() as u32;
        flow.reassembled.extend_from_slice(&data);
        return;
    }

    if seq == flow.next_seq {
        // in-order
        flow.reassembled.extend_from_slice(&data);
        flow.next_seq += data.len() as u32;

        // flush buffered out-of-order segments
        while let Some(buf) = flow.buffer.remove(&flow.next_seq) {
            flow.reassembled.extend_from_slice(&buf);
            flow.next_seq += buf.len() as u32;
        }
    } else {
        // out-of-order
        flow.buffer.insert(seq, data);
    }
}

/// Write flow-level PCAP
fn write_flow_pcap(
    key: &FlowKey,
    pkts: &Vec<Vec<u8>>,
    outdir: &PathBuf,
) {
    let fname = format!("flow_{}_{}_{}_{}.pcap",
        key.src, key.sport, key.dst, key.dport);

    let path = outdir.join(fname);
    let mut file = BufWriter::new(File::create(path).unwrap());
    write_pcap_header(&mut file);

    for p in pkts {
        append_pcap(&mut file, p);
    }
}


/// ----------- PARALLEL CAPTURE LOOP (used by TCP + UDP threads) -----------------

fn capture_loop(
    dev_path: &str,
    proto_name: &str,
    streams_dir: PathBuf,
    captured_dir: PathBuf,
    flows_dir: PathBuf,
) {
    println!("[{proto_name}] Opening device {dev_path}...");

    let mut dev = std::fs::OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_SYNC)
    .open(dev_path)
    .unwrap();


    let rolling_pcap = streams_dir.join(format!("all_{}_streams.pcap", proto_name.to_lowercase()));
    let mut main_pcap = BufWriter::new(File::create(&rolling_pcap).unwrap());
    write_pcap_header(&mut main_pcap);

    println!("[{proto_name}] Rolling PCAP: {:?}", rolling_pcap);

    let mut tcp_flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<FlowKey, UdpFlow> = HashMap::new();

    loop {
    let pkt = read_frame(&mut dev);
    append_pcap(&mut main_pcap, &pkt);

        // flow handling
        if let Some((flow_key, l4_offset)) = parse_flow(&pkt) {
            match flow_key.proto {
                6 => {
                    // TCP
                    let flow = tcp_flows.entry(flow_key.clone()).or_insert(TcpFlow {
                        packets: Vec::new(),
                        next_seq: 0,
                        buffer: HashMap::new(),
                        reassembled: Vec::new(),
                    });

                    flow.packets.push(pkt.clone());
                    handle_tcp(flow, &pkt, l4_offset);

                    // periodically flush
                    if flow.packets.len() >= 50 {
                        write_flow_pcap(&flow_key, &flow.packets, &flows_dir);
                        flow.packets.clear();
                    }
                }

                17 => {
                    // --- UDP packet handling -----------------------------------------

                    // Step 1: handle this packet’s flow
                    let packets_len_after_insert = {
                        let flow = udp_flows.entry(flow_key.clone()).or_insert(UdpFlow {
                            packets: Vec::new(),
                            last_seen: Instant::now(),
                        });

                        flow.last_seen = Instant::now();
                        flow.packets.push(pkt.clone());

                        flow.packets.len()
                    }; // <-- MUTABLE BORROW DROPPED HERE

                    // Step 2: cleanup expired flows
                    udp_flows.retain(|_k, f| f.last_seen.elapsed().as_secs() < 30);

                    // Step 3: flush flow if large enough
                    if packets_len_after_insert >= 20 {
                        if let Some(flow) = udp_flows.get_mut(&flow_key) {
                            write_flow_pcap(&flow_key, &flow.packets, &flows_dir);
                            flow.packets.clear();
                        }
                    }
                }

                _ => {}
            }
        }

        // pattern match system (your original logic)
        let is_ike  = pkt.windows(PATTERN_IKEV2.len()).any(|w| w == PATTERN_IKEV2);
        let is_file = pkt.windows(PATTERN_FILEUPLOAD.len()).any(|w| w == PATTERN_FILEUPLOAD);

        if is_ike || is_file {
            let ts = now_ts();
            let evt_dir = captured_dir.join(format!("{}_evt_{}", proto_name.to_lowercase(), ts));
            create_dir_all(&evt_dir).unwrap();

            // event-level PCAP
            let mut evt_pcap = BufWriter::new(File::create(evt_dir.join("capture.pcap")).unwrap());
            write_pcap_header(&mut evt_pcap);
            append_pcap(&mut evt_pcap, &pkt);

            let desc = if is_ike { "IKEv2 suspect" } else { "FileUpload suspect" };
            let metadata = format!("{{\"ts\":\"{}\", \"proto\":\"{}\", \"match\":\"{}\"}}",
                ts, proto_name, desc);

            std::fs::write(evt_dir.join("metadata.json"), &metadata).unwrap();

            let bundle = [&pkt[..], metadata.as_bytes()].concat();
            let enc = crypto::encrypt_and_compress_bundle(&bundle);
            std::fs::write(evt_dir.join("capture.enc.zst"), enc).unwrap();

            println!("[{proto_name}] Suspect event captured → {ts}");
        }
    }
}


/// ----------- MAIN: start TCP + UDP capture threads --------------------------

fn main() {
    println!("[monitor] Starting full TCP + UDP monitoring engine...");

    let session = now_ts();
    let base = PathBuf::from(format!("output/{session}"));

    let tcp_streams  = base.join("tcp_streams");
    let udp_streams  = base.join("udp_streams");
    let captured     = base.join("captured_patterns");
    let flows_tcp    = base.join("flows/tcp");
    let flows_udp    = base.join("flows/udp");

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
            capture_loop(
                "/dev/suspect_kmod",
                "TCP",
                tcp_streams,
                captured,
                flows_tcp,
            );
        })
    };

    let t2 = {
        let captured = captured.clone();
        let flows_udp = flows_udp.clone();
        let udp_streams = udp_streams.clone();

        thread::spawn(move || {
            capture_loop(
                "/dev/suspect_udp_kmod",
                "UDP",
                udp_streams,
                captured,
                flows_udp,
            );
        })
    };

    t1.join().unwrap();
    t2.join().unwrap();
}
