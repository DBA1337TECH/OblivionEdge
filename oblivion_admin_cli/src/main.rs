mod cli;
mod netlink;
mod auth;

use cli::run_cli;

fn main() {
    if let Err(e) = run_cli() {
        eprintln!("Error: {}", e);
    }
}

