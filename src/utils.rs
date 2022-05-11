use itertools::Itertools;
use std::collections::HashMap;

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

pub fn normalized_hamming_distance(input: &Vec<u8>, keysize: usize) -> f32 {
    let chunks = input.chunks(keysize).combinations(2);

    let mut distance = 0f32;

    for chunk in chunks.into_iter() {
        distance += hamming_distance(&chunk[0].to_vec(), &chunk[1].to_vec()).unwrap() as f32;
    }

    distance /= 6f32;

    distance / keysize as f32
}
