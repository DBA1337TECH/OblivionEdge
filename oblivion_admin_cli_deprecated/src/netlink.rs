use libc;
use nix::sys::socket::{sendto, SockAddr, MsgFlags};
use std::io;
use std::os::unix::io::RawFd;
use nix::unistd::close;

pub fn send_netlink_command(secret: u32, cmd: u8, payload: &str) -> io::Result<()> {
    const NETLINK_ZTNA: libc::c_int = 31;

    // Use libc directly because nix::SockProtocol doesn't support custom protocols
    let sock: RawFd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ZTNA)
    };

    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Build Netlink destination
    let dest = SockAddr::new_netlink(0, 0);

    // Build message
    let mut msg = Vec::new();
    msg.extend(&secret.to_ne_bytes());
    msg.push(cmd);
    msg.extend(payload.as_bytes());

    sendto(sock, &msg, &dest, MsgFlags::empty())?;
    println!("[+] Sent policy to kernel: {}", payload);
    close(sock).ok();

    Ok(())
}

