use openssl::symm::{Cipher, Crypter, Mode};
use std::collections::HashSet;

const AES_BLOCK_SIZE: usize = 16usize;

// CryptoPals Set 1 Challenge 7
pub fn decrypt_aes_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, &key[..], None).unwrap();
    let mut decrypted = vec![0u8; ciphertext.len() + key.len()];
    decrypter
        .update(&ciphertext[..], decrypted.as_mut_slice())
        .unwrap();
    decrypted
}

pub fn encrypt_aes_ecb(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key[..], None).unwrap();
    let mut encrypted = vec![0u8; plaintext.len() + key.len()];
    encrypter
        .update(&plaintext[..], encrypted.as_mut_slice())
        .unwrap();
    encrypted
}

fn is_aes_ecb(data: &Vec<u8>) -> bool {
    let mut blocks: HashSet<[&u8; AES_BLOCK_SIZE]> = HashSet::new();

    for byte_idx in 0..data.len() {
        let mut block = [&0u8; AES_BLOCK_SIZE];
        for block_idx in 0..AES_BLOCK_SIZE {
            let byte = data.get(byte_idx + block_idx);
            match byte {
                Some(byte) => {
                    block[block_idx] = byte;
                }
                None => {
                    block[block_idx] = &0u8;
                }
            }
        }
        if blocks.contains(&block) {
            return true;
        } else {
            blocks.insert(block);
        }
    }

    false
}

// CryptoPals Set 1 Challenge 8
pub fn detect_aes_ecb(ciphertexts: &Vec<Vec<u8>>) -> (usize, Vec<u8>) {
    let mut detected_ecb: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, ciphertext) in ciphertexts.iter().enumerate() {
        if is_aes_ecb(ciphertext) {
            detected_ecb.push((idx, ciphertext.clone()));
        }
    }

    assert_eq!(detected_ecb.len(), 1usize);

    detected_ecb.swap_remove(0)
}
