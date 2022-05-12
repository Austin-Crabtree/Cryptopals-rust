// TODO Add documentation to code in file

// TODO Change code to use decipher message instead of a Hashmap

use crate::utils;
use crate::utils::{hamming_distance, DecipheredMessage};
use itertools::Itertools;
use utils::english_score;

// CryptoPals Set 1 Challenge 2
/// Xor to Vec of bytes with the same length. Then
/// return the resulting Vec of bytes
pub fn fixed_xor(plain: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let iter = plain.iter().zip(key.iter());
    iter.map(|x| x.0 ^ x.1).collect()
}

// TODO Change this function to use map of over the data vector instead of a for loop
/// Xor a Vec of bytes with a single byte. Then
/// return the resulting Vec of bytes
pub fn single_byte_xor(data: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for byte in data.iter() {
        result.push(byte ^ key);
    }
    result
}

// CryptoPals Set 1 Challenge 3
/// Using cryptanalysis find the byte used to xor encipher the ciphertext.
/// Loop through all possible bytes, and at each bytes decipher with the
/// candidate key, obtain a score of how close to an english word is the
/// plaintext and then push all those results to a vector of candidates.
/// Finally sort for the highest english_score and return the result.
pub fn single_byte_bruteforce(cipher: &Vec<u8>) -> DecipheredMessage {
    let mut candidates: Vec<DecipheredMessage> = Vec::new();

    for key in 0..=255u8 {
        let plaintext_bytes = single_byte_xor(&cipher, key);
        let candidate_score = english_score(&plaintext_bytes);
        let result = DecipheredMessage {
            bytes: plaintext_bytes,
            key: Vec::from([key]),
            score: candidate_score,
        };

        candidates.push(result);
    }

    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

    candidates.swap_remove(0)
}

// CryptoPals Set 1 Challenge 4
/// Given a vector of byte vectors find the singular vector that was enciphered
/// with a single byte xor operation. Using the single_byte_bruteforce function
/// find the top score for each Vec and then return the top result of all Vecs.
pub fn find_element_with_single_byte_xor(data: Vec<Vec<u8>>) -> DecipheredMessage {
    let mut candidates: Vec<DecipheredMessage> = Vec::new();
    for data_element in data.iter() {
        let result = single_byte_bruteforce(data_element);
        candidates.push(result);
    }

    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

    candidates.swap_remove(0)
}

// CryptoPals Set 1 Challenge 5
/// Xor encipher a Vec of bytes using a key of bytes. Each byte in the Vec
/// to encipher is xor'ed with a byte from key, with the key bytes rotating
/// in a ring fashion.
pub fn repeating_key_xor(plain: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut cipher: Vec<u8> = Vec::new();
    let key_size = key.len();
    for (i, byte) in plain.iter().enumerate() {
        let idx = i % key_size; // This will grab the idx for the key in a ring till done.
        let key_byte = key[idx];
        cipher.push(byte ^ key_byte);
    }

    cipher
}

// CryptoPals Set 1 Challenge 6
pub fn breaking_repeating_xor(data: &Vec<u8>) -> DecipheredMessage {
    let mut candidate_message = DecipheredMessage::new();

    let mut normalized_distances: Vec<(u32, u32)> = Vec::new();
    for keysize in 2..41u32 {
        let chunks: Vec<&[u8]> = data.chunks(keysize as usize).take(4).collect();
        let pairs = chunks.into_iter().combinations(2).map(|x| x.to_vec());
        let mut distance = 0u32;
        for x in pairs {
            distance += hamming_distance(&x[0].to_vec(), &x[1].to_vec()).unwrap();
        }
        distance /= 6u32;

        let normalized_distance = distance / keysize;
        normalized_distances.push((keysize, normalized_distance));
    }

    normalized_distances.sort_by(|x, y| x.1.cmp(&y.1));

    let possible_keysizes: Vec<&(u32, u32)> = normalized_distances.iter().take(3).collect();

    for keysize in possible_keysizes.iter() {
        let mut key: Vec<u8> = Vec::new();

        for i in 0..keysize.0 {
            let mut block: Vec<u8> = Vec::new();

            for j in (i..data.len() as u32).step_by(keysize.0 as usize) {
                let byte: u8 = data.get(j as usize).unwrap().clone();
                block.push(byte);
            }
            key.push(single_byte_bruteforce(&block).key[0]);
        }
        let candidate_bytes = repeating_key_xor(&data, &key);
        let candidate_score = english_score(&candidate_bytes);
        let candidate = DecipheredMessage {
            bytes: candidate_bytes,
            key,
            score: candidate_score,
        };
        if candidate.score > candidate_message.score {
            candidate_message = candidate;
        }
    }

    candidate_message
}
