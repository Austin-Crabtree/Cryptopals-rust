// TODO Need to add documentation to this file
use crate::utils::{pkcs_7_pad, pkcs_7_unpad};
use crate::xor::repeating_key_xor;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};
use std::collections::HashSet;

const AES_BLOCK_SIZE: usize = 16usize;

// CryptoPals Set 1 Challenge 7
pub fn decrypt_aes_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: Option<&[u8]>) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, &key[..], iv).unwrap();
    let mut decrypted = vec![0u8; ciphertext.len() + key.len()];
    decrypter
        .update(&ciphertext[..], decrypted.as_mut_slice())
        .unwrap();

    let mut result = vec![0u8; ciphertext.len()];
    result = decrypted[0..ciphertext.len()].to_vec();
    result
}

pub fn encrypt_aes_ecb(plaintext: &Vec<u8>, key: &Vec<u8>, iv: Option<&[u8]>) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key[..], iv).unwrap();
    let mut encrypted = vec![0u8; plaintext.len() + key.len()];
    encrypter
        .update(&plaintext[..], encrypted.as_mut_slice())
        .unwrap();

    let mut result = vec![0u8; plaintext.len()];
    result = encrypted[0..plaintext.len()].to_vec();
    result
}

fn is_aes_ecb(data: &Vec<u8>) -> bool {
    let chunks: Vec<&[u8]> = data.chunks(AES_BLOCK_SIZE).collect();
    let mut blocks: HashSet<&[u8]> = HashSet::new();

    for chunk in chunks.iter() {
        blocks.insert(*chunk);
    }

    let num_dups = chunks.len() - blocks.len();

    if num_dups > 0 {
        true
    } else {
        false
    }
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

pub fn decrypt_aes_cbc(
    ciphertext: &Vec<u8>,
    key: &Vec<u8>,
    initial_iv: &Vec<u8>,
    unpad: bool,
) -> Vec<u8> {
    let mut plaintext: Vec<u8> = Vec::new();
    for i in (0..ciphertext.len()).step_by(AES_BLOCK_SIZE) {
        let block = ciphertext[i..i + AES_BLOCK_SIZE].to_vec();
        let decrypted_block = decrypt_aes_ecb(&block, key, None);
        let xor_with = match i {
            0 => initial_iv.clone(),
            _ => ciphertext[i - AES_BLOCK_SIZE..i].to_vec(),
        };
        let mut xor_data = repeating_key_xor(&decrypted_block, &xor_with);
        plaintext.append(xor_data.as_mut());
    }

    if unpad {
        plaintext = pkcs_7_unpad(&plaintext);
    }

    plaintext
}

pub fn encrypt_aes_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, initial_iv: &Vec<u8>) -> Vec<u8> {
    let mut ciphertext: Vec<u8> = Vec::new();
    let padded_data = pkcs_7_pad(&plaintext, &AES_BLOCK_SIZE);
    for i in (0..plaintext.len()).step_by(AES_BLOCK_SIZE) {
        let block = padded_data[i..i + AES_BLOCK_SIZE].to_vec();
        // let padded_data = pkcs_7_pad(&block, AES_BLOCK_SIZE);
        let xor_with = match i {
            0 => initial_iv.clone(),
            _ => ciphertext[i - AES_BLOCK_SIZE..i].to_vec(),
        };
        let cipher_input = repeating_key_xor(&block, &xor_with);
        let mut encrypted_block = encrypt_aes_ecb(&cipher_input, &key, None);
        ciphertext.append(encrypted_block.as_mut());
    }
    ciphertext
}

// TODO Acting non-deterministic need to fix that should get it 100% of the time.
pub fn aes_encryption_oracle(data: &mut Vec<u8>) -> (String, String) {
    let mut rng = thread_rng();
    let key: [u8; AES_BLOCK_SIZE] = rng.gen();
    let mut method: String = "".to_string();
    let amt_append_front: usize = rng.gen_range(5..10);
    let mut front_append_bytes: Vec<u8> = Vec::new();
    for _ in 0..amt_append_front {
        let byte: u8 = rng.gen();
        front_append_bytes.push(byte);
    }
    let amt_apppend_back: usize = rng.gen_range(5..10);
    let mut back_append_bytes: Vec<u8> = Vec::new();
    for _ in 0..amt_apppend_back {
        let byte: u8 = rng.gen();
        back_append_bytes.push(byte);
    }
    let mut plaintext = front_append_bytes;
    plaintext.append(data);
    plaintext.append(back_append_bytes.as_mut());

    let mut ciphertext: Vec<u8> = Vec::new();
    if rng.gen_bool(1.0 / 2.0) {
        method = "ECB".to_string();
        ciphertext = encrypt_aes_ecb(&plaintext, &key.to_vec(), None);
    } else {
        let iv: [u8; AES_BLOCK_SIZE] = rng.gen();
        method = "CBC".to_string();
        ciphertext = encrypt_aes_cbc(&plaintext, &key.to_vec(), &iv.to_vec());
    }

    let mut detected_method: String = "".to_string();
    if is_aes_ecb(&ciphertext) {
        detected_method = "ECB".to_string();
    } else {
        detected_method = "CBC".to_string();
    }

    (method, detected_method)
}
