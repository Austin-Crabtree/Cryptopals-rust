// TODO Add documentation to this file

use std::collections::HashMap;

pub struct DecipheredMessage {
    pub bytes: Vec<u8>,
    pub key: Vec<u8>,
    pub score: f32,
}

impl DecipheredMessage {
    pub fn new() -> DecipheredMessage {
        DecipheredMessage {
            bytes: Vec::new(),
            key: Vec::new(),
            score: -99999f32,
        }
    }
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

/// Given two byte vectors calculate the hamming distance between them.
/// The hamming distance is the amount of bits that need to be flipped
/// for each byte to match.
pub fn hamming_distance(bin_seq1: &Vec<u8>, bin_seq2: &Vec<u8>) -> Result<u32, &'static str> {
    if bin_seq1.len() != bin_seq2.len() {
        return Err("Inputs need to have the same length");
    }

    let differences: Vec<u8> = bin_seq1
        .iter()
        .zip(bin_seq2.iter())
        .map(|(x, y)| x ^ y)
        .collect();

    let ones: Vec<u32> = differences.iter().map(|x| x.count_ones()).collect();

    let distances: u32 = ones.iter().sum();

    Ok(distances)
}

// CryptoPals Set 2 Challenge 9
pub fn pkcs_7_pad(data: &Vec<u8>, block_size: &usize) -> Vec<u8> {
    let mut padded_data = data.clone();
    let pad_len = block_size - data.len() % block_size;
    padded_data.append(vec![pad_len as u8; pad_len].as_mut());
    padded_data.to_vec()
}

fn is_pkcs_7_padded(data: &Vec<u8>) -> bool {
    let pad_len = data[data.len() - 1];
    let padding = data[data.len() - pad_len as usize..data.len() - 1].to_vec();
    for pad_byte in padding.iter() {
        if *pad_byte != pad_len {
            return false;
        }
    }
    true
}

pub fn check_pkcs_7_padding(data: &Vec<u8>) -> Result<Vec<u8>, String> {
    if !is_pkcs_7_padded(&data) {
        return Err("Data not PKCS#7 padded".to_string());
    }

    Ok(pkcs_7_unpad(&data))
}

pub fn pkcs_7_unpad(data: &Vec<u8>) -> Vec<u8> {
    let mut unpadded_data: Vec<u8> = Vec::new();
    if !is_pkcs_7_padded(&data) {
        return data.to_vec();
    }
    let pad_len = data[data.len() - 1];
    unpadded_data = data[0..data.len() - pad_len as usize].to_vec();
    unpadded_data
}
