// TODO Add documentation to code in file

use crate::utils;
// use itertools::Itertools;
use crate::utils::normalized_hamming_distance;
use std::collections::HashMap;
use utils::english_score;

pub fn fixed_xor(plain: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let iter = plain.iter().zip(key.iter());
    iter.map(|x| x.0 ^ x.1).collect()
}

pub fn single_byte_xor(data: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for byte in data.iter() {
        result.push(byte ^ key);
    }
    result
}

pub fn single_byte_bruteforce(cipher: &Vec<u8>) -> HashMap<String, String> {
    let mut candidates: Vec<HashMap<String, String>> = Vec::new();

    for key in 0..=255u8 {
        let plaintext_bytes = single_byte_xor(&cipher, key);
        let plaintext_candidate = String::from_utf8_lossy(&plaintext_bytes);
        let candidate_score = english_score(&plaintext_bytes);
        let result = HashMap::from([
            ("key".to_string(), key.to_string()),
            ("score".to_string(), candidate_score.to_string()),
            (
                "plaintext".to_string(),
                plaintext_candidate.parse().unwrap(),
            ),
        ]);

        candidates.push(result);
    }

    candidates.sort_by(|a, b| b["score"].cmp(&a["score"]));
    // candidates.pop().unwrap()
    candidates.swap_remove(0)
}

pub fn find_element_with_single_byte_xor(data: Vec<Vec<u8>>) -> HashMap<String, String> {
    let mut candidates: Vec<HashMap<String, String>> = Vec::new();
    for data_element in data.iter() {
        let result = single_byte_bruteforce(data_element);
        candidates.push(result);
    }

    candidates.sort_by(|a, b| b["score"].cmp(&a["score"]));

    candidates.swap_remove(0)
}

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

fn generate_key_candidate_sizes(data: &Vec<u8>) -> Vec<u8> {
    let mut distances: Vec<(usize, f32)> = Vec::new();

    for keysize in 2..41 {
        distances.push((keysize, normalized_hamming_distance(&data, keysize)));
    }

    distances.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    let possible_key_sizes: Vec<u8> = distances.iter().take(3).map(|x| x.0 as u8).collect();
    possible_key_sizes
}

pub fn break_repeating_xor(data: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let key_candidate_sizes = generate_key_candidate_sizes(&data);
    let mut possible_plaintexts: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for keysize in key_candidate_sizes.iter() {
        let mut key: Vec<u8> = Vec::new();

        for i in 0..*keysize as usize {
            let mut block: Vec<u8> = Vec::new();

            for j in (i..data.len()).step_by(*keysize as usize) {
                block.push(data[j]);
            }

            key.push(single_byte_bruteforce(&block)["key"].parse::<u8>().unwrap());
        }

        possible_plaintexts.push((repeating_key_xor(&data, &key), key));
    }

    let mut scores: Vec<(Vec<u8>, Vec<u8>, f32)> = Vec::new();

    for plaintext in possible_plaintexts.iter() {
        scores.push((
            plaintext.0.clone(),
            plaintext.1.clone(),
            english_score(&plaintext.0),
        ));
    }

    scores.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());

    let winner = scores.swap_remove(0);
    (winner.0, winner.1)
}
