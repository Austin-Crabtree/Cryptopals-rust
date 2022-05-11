// TODO Add documentation to code in file

use std::collections::HashMap;

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

pub fn english_score(bytes: &Vec<u8>) -> f32 {
    let char_freq = HashMap::from([
        ('a', 0.0651738),
        ('b', 0.0124248),
        ('c', 0.0217339),
        ('d', 0.0349835),
        ('e', 0.1041442),
        ('f', 0.0197881),
        ('g', 0.015861),
        ('h', 0.0492888),
        ('i', 0.0558094),
        ('j', 0.0009033),
        ('k', 0.0050529),
        ('l', 0.033149),
        ('m', 0.0202124),
        ('n', 0.0564513),
        ('o', 0.0596302),
        ('p', 0.0137645),
        ('q', 0.0008606),
        ('r', 0.0497563),
        ('s', 0.051576),
        ('t', 0.0729357),
        ('u', 0.0225134),
        ('v', 0.0082903),
        ('w', 0.0171272),
        ('x', 0.0013692),
        ('y', 0.0145984),
        ('z', 0.0007836),
        (' ', 0.1918182),
    ]);

    let mut score: f32 = 0f32;

    for byte in bytes.iter() {
        let c = *byte as char;
        let value = char_freq.get(&c);
        match value {
            Some(num) => {
                score += num;
            }
            None => (),
        }
    }
    score
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
