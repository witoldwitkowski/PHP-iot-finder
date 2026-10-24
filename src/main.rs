//! iotscan command-line entry point.

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = iotscan::cli::Cli::parse();
    match iotscan::app::run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("iotscan: {e}");
            ExitCode::from(iotscan::app::EXIT_ERROR)
        }
    }
}
