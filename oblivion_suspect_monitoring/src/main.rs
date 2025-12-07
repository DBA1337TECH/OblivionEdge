// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.



mod crypto;
mod packet_pipe;
mod patterns;
use std::io::{Write, BufWriter};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs::create_dir_all;
use std::path::PathBuf;
use patterns::{PATTERN_IKEV2, PATTERN_FILEUPLOAD};



fn write_pcap_file(out_path: &std::path::Path, packets: &[Vec<u8>]) {
    let mut file = BufWriter::new(std::fs::File::create(out_path).unwrap());

    // Global pcap header (little endian)
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // magic number
        0x02, 0x00, 0x04, 0x00, // version major/minor
        0x00, 0x00, 0x00, 0x00, // thiszone
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen
        0x01, 0x00, 0x00, 0x00, // network: Ethernet
    ]).unwrap();

    for pkt in packets {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();

        let len = pkt.len() as u32;

        file.write_all(&ts_sec.to_le_bytes()).unwrap();
        file.write_all(&ts_usec.to_le_bytes()).unwrap();
        file.write_all(&len.to_le_bytes()).unwrap(); // incl_len
        file.write_all(&len.to_le_bytes()).unwrap(); // orig_len
        file.write_all(pkt).unwrap();
    }

    file.flush().unwrap();
}

fn now_ts() -> String {
    let now = chrono::Utc::now();
    now.format("%Y%m%d_%H%M%S").to_string()
}



fn main() {

    while(true){
    let packets = packet_pipe::read_suspect_packets("/dev/suspect_kmod");

    for pkt in packets {
         // pkt.windows(PATTERN_IKEV2.len()).any(|w| w == PATTERN_IKEV2)
            // 
            // 
            // || pkt.windows(PATTERN_FILEUPLOAD.len()).any(|w| w == PATTERN_FILEUPLOAD) {

            let ts = now_ts();
            let outdir = PathBuf::from(format!("output/{}", ts));
            create_dir_all(&outdir).unwrap();

            write_pcap_file(&outdir.join("capture.pcap"), &[pkt.clone()]);
            std::fs::write(outdir.join("payload.bin"), &pkt).unwrap();


            let metadata = format!("{{\"ts\":\"{}\",\"match\":\"Cisco CVE pattern\"}}", ts);
            std::fs::write(outdir.join("metadata.json"), &metadata).unwrap(); // borrow, don't move

            let bundle = [&pkt[..], metadata.as_bytes()].concat(); // ✅ OK to use

            let encrypted = crypto::encrypt_and_compress_bundle(&bundle);
            std::fs::write(outdir.join("capture.enc.zst"), &encrypted).unwrap();
       // }
    }
}
}
