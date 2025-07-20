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
