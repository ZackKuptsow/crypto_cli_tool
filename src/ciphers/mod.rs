pub mod caesar;

pub trait Cipher {
    fn encrypt(&self, plaintext: &str) -> String;
    fn decrypt(&self, ciphertext: &str) -> String;
}

pub use caesar::CaesarCipher;
