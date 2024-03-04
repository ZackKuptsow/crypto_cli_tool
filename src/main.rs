use clap::Parser;
use std::process;

#[derive(clap::ArgEnum, Clone, Debug)]
enum Algorithm {
    #[clap(name = "caeser", alias = "c")]
    Caeser,
}

#[derive(clap::ArgEnum, Clone, Debug)]
enum Direction {
    #[clap(name = "encrypt", alias = "e")]
    Encrypt,
    #[clap(name = "decrypt", alias = "d")]
    Decrypt
}

#[derive(Parser, Debug)]
// #[command(version, about, long_about = None)]
struct Args {
    // encryption algorithm to use
    #[clap(short, long, arg_enum)]
    algorithm: Algorithm,

    // encrypt/decrypt direction
    #[clap(short, long, arg_enum)]
    direction: Direction,

    // encryption/decryption key
    #[clap(short = 'k', long)]
    key: i32,

    // in decryption mode, brute force
    #[clap(short = 'b', long)]
    brute_force: bool,
}

fn main() {
    let args = Args::parse();

    // check for invalid combination of arguments:
    // brute force can only be done in decrypt mode
    if args.brute_force && matches!(args.direction, Direction::Encrypt) {
        eprintln!("Error: Brute force mode cannot be used with encryption.");
        process::exit(1); // Exit with a non-zero status code to indicate an error
    }

    println!("Algorithm: {:?}", args.algorithm);
    println!("Direction: {:?}", args.direction);
    println!("Key: {}", args.key);
    println!("Brute Force: {}", args.brute_force);
}
