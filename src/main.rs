mod ciphers;
use ciphers::Cipher;

use clap::Parser;
use std::process;
use std::str::FromStr;

#[derive(clap::ArgEnum, Clone, Debug)]
enum Algorithm {
    #[clap(name = "caesar", alias = "c")]
    Caesar,
    #[clap(name = "vigenere", alias = "v")]
    Vigenère,
    #[clap(name = "playfair", alias = "p")]
    Playfair,
}

#[derive(clap::ArgEnum, Clone, Debug)]
enum Direction {
    #[clap(name = "encrypt", alias = "e")]
    Encrypt,
    #[clap(name = "decrypt", alias = "d")]
    Decrypt,
}

#[derive(Clone, Debug)]
enum KeyType {
    Integer(i32),
    Text(String),
}

impl FromStr for KeyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(i) = s.parse::<i32>() {
            Ok(KeyType::Integer(i))
        } else {
            Ok(KeyType::Text(s.to_string()))
        }
    }
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
    key: KeyType,

    // in decryption mode, brute force
    #[clap(short = 'b', long)]
    brute_force: bool,

    input_text: String,
}

fn main() {
    let args = Args::parse();

    // Check for invalid combination of arguments:
    // Brute force can only be done in decrypt mode
    if args.brute_force && matches!(args.direction, Direction::Encrypt) {
        eprintln!("Error: Brute force mode cannot be used with encryption.");
        process::exit(1); // Exit with a non-zero status code to indicate an error
    }

    let cipher: Box<dyn Cipher> = match args.algorithm {
        Algorithm::Caesar => {
            if let KeyType::Integer(key) = args.key {
                Box::new(ciphers::caesar::CaesarCipher { key })
            } else {
                panic!("Caesar cipher requires an integer key.");
            }
        }
        Algorithm::Vigenère => {
            if let KeyType::Text(key) = args.key {
                Box::new(ciphers::vigenere::VigenereCipher::new(key))
            } else {
                panic!("Vigenère cipher requires a text key.");
            }
        }
        Algorithm::Playfair => {
            if let KeyType::Text(key) = args.key {
                Box::new(ciphers::playfair::PlayfairCipher::new(key))
            } else {
                panic!("Playfair cipher requires a text key.")
            }
        }
    };

    let output_text = match args.direction {
        Direction::Encrypt => cipher.encrypt(&args.input_text),
        Direction::Decrypt => cipher.decrypt(&args.input_text),
    };

    println!("Algorithm: {:?}", args.algorithm);
    println!("Direction: {:?}", args.direction);
    println!("Output: {}\n", output_text);
}
