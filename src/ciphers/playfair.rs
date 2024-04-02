//! The `playfair` module provides an implementation of the Playfair cipher

use super::Cipher;
use std::collections::HashSet;

enum EncryptionDirection {
    Encrypt,
    Decrypt,
}

/// A `PlayfairCipher` represents the Playfair cipher encryption algorithm
/// It shifts bigrams of the plaintext according to a 5x5 matrix
pub struct PlayfairCipher {
    pub key: String,
    matrix: [[char; 5]; 5],
}

impl PlayfairCipher {
    fn clean_key_on_new(&mut self, key: &str) {
        let mut seen = HashSet::new();
        for c in key.to_ascii_uppercase().chars() {
            if c == 'J' {
                continue;
            }
            if seen.insert(c) {
                self.key.push(c);
            }
        }
    }

    fn generate_matrix(&mut self) {
        let mut matrix: [[char; 5]; 5] = [[' '; 5]; 5];
        let mut seen: HashSet<char> = HashSet::new();

        let mut index: usize = 0;
        for c in self.key.chars() {
            matrix[index / 5][index % 5] = c;
            seen.insert(c);
            index += 1;
        }

        for c in ('A'..='Z').filter(|&c| c != 'J' && !seen.contains(&c)) {
            matrix[index / 5][index % 5] = c;
            index += 1;
        }

        self.matrix = matrix;
    }

    fn get_char_indexes(&self, mut target: char) -> (usize, usize) {
        if target == 'J' {
            target = 'X';
        }

        for (row_index, row) in self.matrix.iter().enumerate() {
            if let Some(col_index) = row.iter().position(|&c| c == target) {
                return (row_index, col_index);
            }
        }

        panic!("Character not found in matrix, which should never happen");
    }

    pub fn new(key: String) -> Self {
        let mut cipher = PlayfairCipher {
            key: String::new(),
            matrix: [[' '; 5]; 5],
        };
        cipher.clean_key_on_new(&key);
        cipher.generate_matrix();
        cipher
    }

    fn swap_chars(
        &self,
        primary_char: char,
        mut secondary_char: char,
        direction: EncryptionDirection,
    ) -> (char, char) {
        if primary_char == secondary_char {
            secondary_char = 'X';
        }

        let (primary_row_index, primary_col_index) = self.get_char_indexes(primary_char);
        let (secondary_row_index, secondary_col_index) = self.get_char_indexes(secondary_char);

        let translation: i8 = match direction {
            EncryptionDirection::Encrypt => 1,
            EncryptionDirection::Decrypt => -1,
        };

        match (
            primary_row_index == secondary_row_index,
            primary_col_index == secondary_col_index,
        ) {
            (true, _) => (
                self.matrix[primary_row_index]
                    [(((primary_col_index as i8 + translation) % 5 + 5) % 5) as usize],
                self.matrix[secondary_row_index]
                    [(((secondary_col_index as i8 + translation) % 5 + 5) % 5) as usize],
            ),
            (_, true) => (
                self.matrix[(((primary_row_index as i8 + translation) % 5 + 5) % 5) as usize]
                    [primary_col_index],
                self.matrix[(((secondary_row_index as i8 + translation) % 5 + 5) % 5) as usize]
                    [secondary_col_index],
            ),
            (false, false) => (
                self.matrix[primary_row_index][secondary_col_index],
                self.matrix[secondary_row_index][primary_col_index],
            ),
        }
    }
}

impl Cipher for PlayfairCipher {
    fn encrypt(&self, plaintext: &str) -> String {
        let mut plaintext_string = plaintext.to_string();
        if plaintext_string.len() % 2 != 0 {
            plaintext_string.push('x');
        }

        let mut ciphertext: String = String::with_capacity(plaintext_string.len());
        for i in (0..plaintext.len()).step_by(2) {
            let primary_plaintext_char = plaintext_string.chars().nth(i).unwrap();
            let secondary_plaintext_char = plaintext_string.chars().nth(i + 1).unwrap();

            let (mut primary_ciphertext_char, mut secondary_ciphertext_char) = self.swap_chars(
                primary_plaintext_char.to_ascii_uppercase(),
                secondary_plaintext_char.to_ascii_uppercase(),
                EncryptionDirection::Encrypt,
            );

            primary_ciphertext_char = match primary_plaintext_char.is_ascii_uppercase() {
                true => primary_ciphertext_char,
                false => primary_ciphertext_char.to_ascii_lowercase(),
            };
            secondary_ciphertext_char = match secondary_plaintext_char.is_ascii_uppercase() {
                true => secondary_ciphertext_char,
                false => secondary_ciphertext_char.to_ascii_lowercase(),
            };

            ciphertext.push(primary_ciphertext_char);
            ciphertext.push(secondary_ciphertext_char);
        }

        ciphertext
    }

    fn decrypt(&self, ciphertext: &str) -> String {
        let mut ciphertext_string = ciphertext.to_string();
        if ciphertext_string.len() % 2 != 0 {
            ciphertext_string.push('x');
        }

        let mut plaintext: String = String::with_capacity(ciphertext_string.len());
        for i in (0..ciphertext_string.len()).step_by(2) {
            let (primary_char, secondary_char) = self.swap_chars(
                ciphertext_string.chars().nth(i).unwrap(),
                ciphertext_string.chars().nth(i + 1).unwrap(),
                EncryptionDirection::Decrypt,
            );
            plaintext.push(primary_char);
            plaintext.push(secondary_char);
        }

        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_matrix() {
        let cipher: PlayfairCipher = PlayfairCipher::new("keyword");
        let expected: [[char; 5]; 5] = [
            ['K', 'E', 'Y', 'W', 'O'],
            ['R', 'D', 'A', 'B', 'C'],
            ['F', 'G', 'H', 'I', 'L'],
            ['M', 'N', 'P', 'Q', 'S'],
            ['T', 'U', 'V', 'X', 'Z'],
        ];

        assert_eq!(cipher.matrix, expected);
    }

    #[test]
    fn test_get_char_indexes() {
        let cipher: PlayfairCipher = PlayfairCipher::new("keyword");

        let (char_row, char_col) = cipher.get_char_indexes('C');
        let (expected_row, expected_col) = (1, 4);

        assert_eq!(char_row, expected_row);
        assert_eq!(char_col, expected_col);
    }

    #[test]
    fn test_swap_chars() {
        let cipher: PlayfairCipher = PlayfairCipher::new("keyword");

        let (primary_row_swap_char, secondary_row_swap_char) =
            cipher.swap_chars('D', 'B', EncryptionDirection::Encrypt);
        let (primary_col_swap_char, secondary_col_swap_char) =
            cipher.swap_chars('D', 'N', EncryptionDirection::Encrypt);
        let (primary_wrap_row_char, secondary_wrap_row_char) =
            cipher.swap_chars('F', 'L', EncryptionDirection::Encrypt);
        let (primary_wrap_col_char, secondary_wrap_col_char) =
            cipher.swap_chars('Y', 'V', EncryptionDirection::Encrypt);
        let (primary_square_swap_char, secondary_square_swap_char) =
            cipher.swap_chars('D', 'Q', EncryptionDirection::Encrypt);

        assert_eq!(primary_row_swap_char, 'A');
        assert_eq!(secondary_row_swap_char, 'C');
        assert_eq!(primary_col_swap_char, 'G');
        assert_eq!(secondary_col_swap_char, 'U');
        assert_eq!(primary_wrap_row_char, 'G');
        assert_eq!(secondary_wrap_row_char, 'F');
        assert_eq!(primary_wrap_col_char, 'A');
        assert_eq!(secondary_wrap_col_char, 'Y');
        assert_eq!(primary_square_swap_char, 'B');
        assert_eq!(secondary_square_swap_char, 'N');
    }

    #[test]
    fn test_playfair_cipher_encrypt() {
        let cipher: PlayfairCipher = PlayfairCipher::new("keyword");
        let ciphertext1 = cipher.encrypt("SECRET");
        let ciphertext2 = cipher.encrypt("secret");

        assert_eq!(ciphertext1, "NORDKU");
        assert_eq!(ciphertext2, "nordku");
    }

    #[test]
    fn test_playfair_cipher_decrypt() {
        let cipher: PlayfairCipher = PlayfairCipher::new("keyword");
        let plaintext = cipher.decrypt("NORDKU");

        assert_eq!(plaintext, "SECRET");
    }
}
