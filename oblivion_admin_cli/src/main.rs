mod ioctl;
mod cli;

use cli::{OblivionCmd, RouteArgs, FwArgs};
use ioctl::{router::*, firewall::*};
use clap::Parser;
use std::net::Ipv4Addr;
use std::ffi::CString;
use std::str::FromStr;

fn main() {
    let cmd = OblivionCmd::parse();

    match cmd {
        OblivionCmd::Route(args) => {
            let route = RouteEntry {
                dest: u32::from(Ipv4Addr::from_str(&args.dst).unwrap()).to_be(),
                gateway: u32::from(Ipv4Addr::from_str(&args.gw).unwrap()).to_be(),
                netmask: u32::from(Ipv4Addr::from_str(&args.netmask).unwrap()).to_be(),
                ifname: {
                    let mut buf = [0; 16];
                    let name = CString::new(args.iface).unwrap().into_bytes_with_nul();
                    buf[..name.len()].copy_from_slice(&name);
                    buf
                },
            };
            add_route(&route).expect("Failed to add route");
        }

        OblivionCmd::Fw(args) => {
            let rule = FirewallRule {
                src_ip: u32::from(Ipv4Addr::from_str(&args.src).unwrap()).to_be(),
                dst_port: args.dport.to_be(),
                action: {
                    let mut buf = [0; 8];
                    let act = CString::new(args.action).unwrap().into_bytes_with_nul();
                    buf[..act.len()].copy_from_slice(&act);
                    buf
                },
            };
            add_firewall_rule(&rule).expect("Failed to add firewall rule");
        }
    }
}
