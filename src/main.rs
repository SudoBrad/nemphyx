use clap::Parser;

use nemphyx::{Args, run};

fn main() {
    let args = Args::parse();
    if let Err(error) = run(args) {
        eprintln!("Error: {}.", error);
        std::process::exit(1);
    }
}
