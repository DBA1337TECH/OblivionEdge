use libc::c_char;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use nix::ioctl_write_ptr;

#[repr(C)]
#[derive(Debug)]
pub struct RouteEntry {
    pub dest: u32,
    pub gateway: u32,
    pub netmask: u32,
    pub ifname: [c_char; 16],
}

ioctl_write_ptr!(add_route_ioctl, b'R', 1, RouteEntry);

pub fn add_route(route: &RouteEntry) -> nix::Result<()> {
    let file = File::options().write(true).open("/dev/router_kmod")?;
    unsafe { add_route_ioctl(file.as_raw_fd(), route) }
}
