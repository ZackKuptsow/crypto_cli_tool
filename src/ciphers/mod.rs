pub mod caesar;
pub mod playfair;
pub mod vigenere;

pub trait Cipher {
    fn encrypt(&self, plaintext: &str) -> String;
    fn decrypt(&self, ciphertext: &str) -> String;
}

pub use caesar::CaesarCipher;
pub use playfair::PlayfairCipher;
pub use vigenere::VigenereCipher;
