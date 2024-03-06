//! The `vigenere` module provides an implementation of the Vigenère cipher

use super::Cipher;

enum EncryptionDirection {
    Encrypt,
    Decrypt,
}
enum LetterCase {
    Upper,
    Lower,
}

pub struct VigenereCipher {
    pub key: String,
}

impl VigenereCipher {
    /// New function to ensure that key is always lowercase.
    ///
    /// # Arguments
    /// * `key` - A String that acts as the key for the vigenere cipher.
    ///
    /// # Returns
    /// A `VigenereCipher` instance that is guaranteed to have
    /// an all lowercase key.
    pub fn new(key: String) -> VigenereCipher {
        VigenereCipher {
            key: key.to_ascii_lowercase(),
        }
    }
}

impl Cipher for VigenereCipher {
    /// Encrypts the given plaintext string slice by shifting by the key's values.
    ///
    /// Always treats key as all lowercase regardless of key's casing.
    /// See `new` function.
    ///
    /// # Arguments
    /// * `plaintext` - A string slice that holds the text to be encrypted.
    ///
    /// # Returns
    /// A `String` containing the encrypted text.
    ///
    /// # Examples
    /// ```
    /// use crypto_cli_tool::ciphers::vigenere::VigenereCipher;
    /// use crypto_cli_tool::ciphers::Cipher;
    ///
    /// let cipher = VigenereCipher::new("key")
    /// assert_eq!(cipher.encrypt("secret"), "ciabar")
    /// ```
    fn encrypt(&self, plaintext: &str) -> String {
        plaintext
            .chars()
            .enumerate()
            .map(|(i, c)| match c.is_ascii_alphabetic() {
                true => shift_char(
                    c,
                    self.key.chars().nth(i % self.key.len()).unwrap(),
                    EncryptionDirection::Encrypt,
                ),
                false => c,
            })
            .collect()
    }

    /// Decrypts the given ciphertext string slice by shifting by the key's values.
    ///
    /// Always treats key as all lowercase regardless of key's casing.
    /// See `new` function.
    ///
    /// # Arguments
    /// * `ciphertext` - A string slice that holds the text to be decrypted.
    ///
    /// # Returns
    /// A `String` containing the decrypted text.
    ///
    /// # Examples
    /// ```
    /// use crypto_cli_tool::ciphers::vigenere::VigenereCipher;
    /// use crypto_cli_tool::ciphers::Cipher;
    ///
    /// let cipher = VigenereCipher::new("key")
    /// assert_eq!(cipher.decrypt("ciabar"), "secret")
    /// ```
    fn decrypt(&self, ciphertext: &str) -> String {
        ciphertext
            .chars()
            .enumerate()
            .map(|(i, c)| match c.is_ascii_alphabetic() {
                true => shift_char(
                    c,
                    self.key.chars().nth(i % self.key.len()).unwrap(),
                    EncryptionDirection::Decrypt,
                ),
                false => c,
            })
            .collect()
    }
}

/// Function to shift a single `char` by another `char`'s value.
///
/// # Arguments
/// * `base_char` - `char` to be shifted.
/// * `key_char` - `char` to shift `base_char`.
/// * `direction` - encrypt or decrypt as direction.
///
/// # Returns
/// Shifted `char`.
///
/// # Examples
/// ```
/// use crypto_cli_tool::ciphers::vigenere::shift_char;
/// let b = "b".chars().next().unwrap();
/// let c = "c".chars().next().unwrap();
/// let d = "d".chars().next().unwrap();
///
/// let encrypted_char = shift_char(b, c, EncryptionDirection::Encrypt);
/// assert_eq!(encrypted_char, d);
/// ```
fn shift_char(base_char: char, key_char: char, direction: EncryptionDirection) -> char {
    let case = match base_char.is_ascii_lowercase() {
        true => LetterCase::Lower,
        false => LetterCase::Upper,
    };
    let base_char_value = base_char.to_ascii_lowercase() as u8 - b'a';
    let key_char_value = key_char as u8 - b'a';
    let result = match direction {
        EncryptionDirection::Encrypt => (base_char_value + key_char_value) % 26 + b'a',
        EncryptionDirection::Decrypt => {
            ((base_char_value as i16 - key_char_value as i16).rem_euclid(26) + b'a' as i16) as u8
        }
    };

    match case {
        LetterCase::Lower => result as char,
        LetterCase::Upper => (result as char).to_ascii_uppercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_char() {
        let b = "b".chars().next().unwrap();
        let c = "c".chars().next().unwrap();
        let d = "d".chars().next().unwrap();
        let encrypted_char = shift_char(b, c, EncryptionDirection::Encrypt);
        let decrypted_char = shift_char(d, c, EncryptionDirection::Decrypt);

        assert_eq!(encrypted_char, d);
        assert_eq!(decrypted_char, b);
    }

    #[test]
    fn test_vigenere_cipher_encrypt() {
        let cipher = VigenereCipher::new("key".to_string());
        let ciphertext = cipher.encrypt("secret");

        assert_eq!(ciphertext, "ciabir")
    }

    #[test]
    fn test_vigenere_cipher_decrypt() {
        let cipher = VigenereCipher::new("key".to_string());
        let plaintext = cipher.decrypt("ciabir");

        assert_eq!(plaintext, "secret")
    }
}
