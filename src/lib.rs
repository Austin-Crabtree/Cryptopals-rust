extern crate hex;

mod b64;
mod xor;

#[cfg(test)]
mod tests {
    use crate::{b64, xor};
    use std::fs;

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
        let cipher =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let answer = "Cooking MC's like a pound of bacon".to_string();
        let result = xor::single_byte_bruteforce(&cipher);
        assert_eq!(result["plaintext"], answer);
    }

    #[test]
    fn test_finding_single_byte_xor() {
        let filename = "test_data/4.txt";
        let contents = fs::read_to_string(filename).unwrap();
        let data: Vec<&str> = contents.split("\n").collect();
        let data_elements: Vec<Vec<u8>> = data.iter().map(|x| hex::decode(x).unwrap()).collect();
        let answer = "Now that the party is jumping\n".to_string();
        let result = xor::find_element_with_single_byte_xor(data_elements);
        assert_eq!(result["plaintext"], answer)
    }

    #[test]
    fn test_repeating_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .to_vec();
        let key = "ICE".as_bytes().to_vec();
        let answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let result = xor::repeating_key_xor(&plaintext, &key);
        let result = hex::encode(result);
        assert_eq!(result, answer);
    }
}
