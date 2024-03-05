mod ciphers;
use ciphers::Cipher;

use clap::Parser;
use std::process;

#[derive(clap::ArgEnum, Clone, Debug)]
enum Algorithm {
    #[clap(name = "caesar", alias = "c")]
    Caesar,
}

#[derive(clap::ArgEnum, Clone, Debug)]
enum Direction {
    #[clap(name = "encrypt", alias = "e")]
    Encrypt,
    #[clap(name = "decrypt", alias = "d")]
    Decrypt,
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

    input_text: String,
}

fn main() {
    let args = Args::parse();

    // check for invalid combination of arguments:
    // brute force can only be done in decrypt mode
    if args.brute_force && matches!(args.direction, Direction::Encrypt) {
        eprintln!("Error: Brute force mode cannot be used with encryption.");
        process::exit(1); // Exit with a non-zero status code to indicate an error
    }

    let cipher = match args.algorithm {
        Algorithm::Caesar => ciphers::caesar::CaesarCipher { key: args.key },
    };

    let output_text = match args.direction {
        Direction::Encrypt => cipher.encrypt(&args.input_text),
        Direction::Decrypt => cipher.decrypt(&args.input_text),
    };

    println!("Algorithm: {:?}", args.algorithm);
    println!("Direction: {:?}", args.direction);
    print!("Output: {}\n", output_text);
}
