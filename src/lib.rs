extern crate hex;

mod b64;
mod xor;

#[cfg(test)]
mod tests {
    use crate::{b64, xor};

    #[test]
    fn test_b64_encode() {
        let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        let answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        assert_eq!(b64::b64_encode(&input), answer);
    }

    #[test]
    fn test_b64_decode() {
        let input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        let answer = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();
        let result = b64::b64_decode(input).unwrap();
        assert_eq!(hex::encode(result), answer);
    }

    #[test]
    fn test_fixed_xor_no_encode() {
        let plain = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let key = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let answer = hex::decode("746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(xor::fixed_xor(&plain, &key), answer);
    }

    #[test]
    fn test_fixed_xor_with_encode() {
        let plain = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let key = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let result = hex::encode(xor::fixed_xor(&plain, &key));
        let answer = "746865206b696420646f6e277420706c6179".to_string();
        assert_eq!(result, answer);
    }

    #[test]
    fn test_brute_force_single_byte_xor() {
        let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let answer = "Cooking MC's like a pound of bacon".to_string();
        let result = xor::single_byte_bruteforce(&cipher);
        assert_eq!(result["plaintext"], answer);
    }
}
