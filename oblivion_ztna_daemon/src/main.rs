use std::os::unix::io::RawFd;
use std::thread;
use nix::sys::socket::*;
use nix::unistd::close;

const NETLINK_ZTNA: isize = 31;

fn main() -> nix::Result<()> {
    let sock = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::empty(), NETLINK_ZTNA)?;

    let addr = SockAddr::Netlink(NetlinkAddr::new(0, 0));
    bind(sock, &addr)?;

    println!("[ZTNA] Userland daemon listening...");

    loop {
        let mut buf = [0u8; 128];
        match recv(sock, &mut buf) {
            Ok(size) => {
                if size > 0 {
                    let msg = String::from_utf8_lossy(&buf[..size]);
                    println!("[ZTNA Event] {msg}");
                    // TODO: lookup hash, compare to threat database
                }
            },
            Err(e) => {
                eprintln!("Receive error: {e}");
                break;
            }
        }
    }

    close(sock)?;
    Ok(())
}
