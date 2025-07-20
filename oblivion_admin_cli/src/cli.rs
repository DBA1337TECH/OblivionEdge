// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.


use clap::{Subcommand, Args, Parser};

#[derive(Parser)]
#[command(name = "oblivion", version = "0.1.0", author = "Oblivion Edge")]
pub struct OblivionCli {
    #[command(subcommand)]
    pub command: OblivionCmd,
}

#[derive(Subcommand)]
pub enum OblivionCmd {
    Route(RouteArgs),
    Fw(FwArgs),
}

#[derive(Args)]
pub struct RouteArgs {
    #[arg(long)] pub dst: String,
    #[arg(long)] pub gw: String,
    #[arg(long)] pub netmask: String,
    #[arg(long)] pub iface: String,
}

#[derive(Args)]
pub struct FwArgs {
    #[arg(long)] pub src: String,
    #[arg(long)] pub dport: u16,
    #[arg(long)] pub action: String,
}
