//! The `caesar` module provides an implementation of the Caesar cipher

use super::Cipher;

/// A `CaesarCipher` represents the Caesar cipher encryption algorithm.
/// It shifts plaintext by a fixed number to encrypt
/// and shifts in the reverse direction by that same fixed number to decrypt
pub struct CaesarCipher {
    pub key: i32,
}

impl Cipher for CaesarCipher {
    /// Encrypts the given plaintext string by shifting the letters by the given key.
    ///
    /// # Arguments
    /// * `plaintext` - A string slice that holds the text to be encrypted.
    ///
    /// # Returns
    /// A `String` containing the encrypted text.
    ///
    /// # Examples
    /// ```
    /// use crypto_cli_tool::ciphers::caesar::CaesarCipher;
    /// use crypto_cli_tool::ciphers::Cipher;
    ///
    /// let cipher = CaesarCipher { key: 3 };
    /// assert_eq!(cipher.encrypt("abc"), "def");
    /// ```
    fn encrypt(&self, plaintext: &str) -> String {
        let shift = self.key.rem_euclid(26) as u8;
        plaintext
            .chars()
            .map(|c| match c.is_ascii_alphabetic() {
                true => {
                    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                    let offset = c as u8 - base;
                    let encrypted = (offset + shift) % 26 + base;
                    encrypted as char
                }
                false => c,
            })
            .collect()
    }

    /// Decrypts the given ciphertext sttring by shifting the letters by the given key.
    ///
    /// Leverages the relationship that decryption is the same but with negative key.
    ///
    /// # Arguments
    /// * `ciphertext` - A string slice that holds the text to be decrypted.
    ///
    /// # Returns
    /// A `String` containing the decrypted text.
    ///
    /// # Examples
    /// ```
    /// use crypto_cli_tool::ciphers::caesar::CaesarCipher;
    /// use crypto_cli_tool::ciphers::Cipher;
    ///
    /// let cipher = CaesarCipher { key: 3 };
    /// assert_eq!(cipher.decrypt("def"), "abc");
    /// ```
    fn decrypt(&self, ciphertext: &str) -> String {
        let cipher = CaesarCipher { key: -self.key };
        cipher.encrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caesar_cipher_encrypt() {
        let cipher = CaesarCipher { key: 13 };
        let ciphertext = cipher.encrypt("test");

        assert_eq!(ciphertext, "grfg");
    }

    #[test]
    fn test_caesar_cipher_decrypt() {
        let cipher = CaesarCipher { key: 13 };
        let plaintext = cipher.decrypt("grfg");

        assert_eq!(plaintext, "test");
    }
}
