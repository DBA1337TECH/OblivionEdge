use clap::{Parser, Subcommand};
use crate::netlink::send_netlink_command;
use crate::auth::get_auth_token;

#[derive(Parser)]
#[command(author = "Oblivion", version, about = "ZTNA Admin CLI")]
pub struct AdminCli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show ZTNA engine status
    Status,
    /// Add a ZTNA policy rule
    Add {
        #[arg(short, long)]
        src: String,
        #[arg(short, long)]
        dst: String,
        #[arg(short, long)]
        proto: String,
        #[arg(short, long)]
        port: u16,
    },
}

pub fn run_cli() -> std::io::Result<()> {
    let cli = AdminCli::parse();
    let token = get_auth_token();

    match cli.command {
        Commands::Status => {
            println!("ZTNA Engine is active.");
            // Could extend this to fetch kernel stats via netlink
        }
        Commands::Add { src, dst, proto, port } => {
            let payload = format!("src={} dst={} proto={} port={}", src, dst, proto, port);
            send_netlink_command(token, 0x01, &payload)?;
        }
    }

    Ok(())
}

