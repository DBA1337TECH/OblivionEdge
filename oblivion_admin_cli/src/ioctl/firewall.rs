// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.


use libc::{c_char, c_ushort, c_uint};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use nix::ioctl_write_ptr;

#[repr(C)]
#[derive(Debug)]
pub struct FirewallRule {
    pub src_ip: c_uint,
    pub dst_port: c_ushort,
    pub action: [c_char; 8],
}

ioctl_write_ptr!(add_fw_rule_ioctl, b'F', 1, FirewallRule);

pub fn add_firewall_rule(rule: &FirewallRule) -> nix::Result<()> {
    let file = File::options().write(true).open("/dev/fw_kmod")?;
    unsafe { add_fw_rule_ioctl(file.as_raw_fd(), rule) }
}
