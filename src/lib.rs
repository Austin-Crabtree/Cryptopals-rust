extern crate hex;

mod aes;
mod b64;
mod utils;
mod xor;

#[cfg(test)]
mod tests {
    use crate::aes::{
        aes_encryption_oracle, decrypt_aes_cbc, decrypt_aes_ecb, detect_aes_ecb, encrypt_aes_cbc,
        encrypt_aes_ecb,
    };
    use crate::b64::b64_decode;
    use crate::utils::pkcs_7_pad;
    use crate::xor::breaking_repeating_xor;
    use crate::{b64, utils, xor};
    use openssl::symm::{Cipher, Crypter, Mode};
    use std::fs;

    // CryptoPals Set 1 Challenge 1
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
        let result = b64_decode(&input).unwrap();
        assert_eq!(hex::encode(result), answer);
    }

    // CryptoPals Set 1 Challenge 2
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

    // CryptoPals Set 1 Challenge 3
    #[test]
    fn test_brute_force_single_byte_xor() {
        let cipher =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let answer = "Cooking MC's like a pound of bacon".to_string();
        let result = xor::single_byte_bruteforce(&cipher);
        let plaintext = String::from_utf8_lossy(result.bytes.as_slice());
        assert_eq!(plaintext, answer);
    }

    // CryptoPals Set 1 Challenge 4
    #[test]
    fn test_finding_single_byte_xor() {
        let filename = "test_data/4.txt";
        let contents = fs::read_to_string(filename).unwrap();
        let data: Vec<&str> = contents.split("\n").collect();
        let data_elements: Vec<Vec<u8>> = data.iter().map(|x| hex::decode(x).unwrap()).collect();
        let answer = "Now that the party is jumping\n".to_string();
        let result = xor::find_element_with_single_byte_xor(data_elements);
        let plaintext = String::from_utf8_lossy(result.bytes.as_slice());
        assert_eq!(plaintext, answer)
    }

    // CryptoPals Set Challenge 5
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

    #[test]
    fn test_hamming_distance() {
        let seq1 = "this is a test".as_bytes().to_vec();
        let seq2 = "wokka wokka!!!".as_bytes().to_vec();
        let dist = utils::hamming_distance(&seq1, &seq2).unwrap();
        assert_eq!(dist, 37);
    }

    // CryptoPals Set 1 Challenge 6
    #[test]
    fn test_breaking_repeating_xor() {
        let filename = "test_data/6.txt";
        let ciphertext = fs::read_to_string(filename).unwrap();
        let ciphertext = ciphertext.split("\n").collect();
        let cipherbytes = b64_decode(&ciphertext).unwrap();
        let result = breaking_repeating_xor(&cipherbytes);
        let answer = "Terminator X: Bring the noise".to_string();
        let key = String::from_utf8_lossy(result.key.as_slice());
        assert_eq!(key, answer);
    }

    // CryptoPals Set 1 Challenge 7
    #[test]
    fn test_decrypting_aes_ecb() {
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let filename = "test_data/7.txt";
        let ciphertext =
            b64_decode(&fs::read_to_string(filename).unwrap().split('\n').collect()).unwrap();
        let result = decrypt_aes_ecb(&ciphertext, &key, None);
        let answer = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}".to_string();
        assert_eq!(String::from_utf8_lossy(result.as_slice()), answer);
    }

    #[test]
    fn test_encrypting_aes_ecb() {
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let filename = "test_data/7.txt";
        let ciphertext =
            b64_decode(&fs::read_to_string(filename).unwrap().split('\n').collect()).unwrap();
        let plaintext = decrypt_aes_ecb(&ciphertext, &key, None);
        let round2 = encrypt_aes_ecb(&plaintext, &key, None);
        let result = decrypt_aes_ecb(&round2, &key, None);
        let answer = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}".to_string();
        assert_eq!(String::from_utf8_lossy(result.as_slice()), answer);
    }

    // CryptoPals Set 1 Challenge 8
    #[test]
    fn test_detecting_aes_ecb() {
        let filename = "test_data/8.txt";
        let contents = fs::read_to_string(filename).unwrap();
        let contents: Vec<String> = contents.split('\n').map(|x| x.to_string()).collect();
        let ciphertexts: Vec<Vec<u8>> = contents.iter().map(|x| b64_decode(&x).unwrap()).collect();
        let result = detect_aes_ecb(&ciphertexts);
        let answer = 132usize;
        assert_eq!(result.0, answer);
    }

    #[test]
    fn test_pkcs_7_padding() {
        let data = "YELLOW SUBMARINE".as_bytes().to_vec();
        let block_size = 20usize;
        let answer = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec();
        let result = pkcs_7_pad(&data, block_size);
        assert_eq!(result, answer);
    }

    #[test]
    fn test_decrypting_aes_cbc() {
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let iv = [0u8; 16usize];
        let filename = "test_data/10.txt";
        let ciphertext =
            b64_decode(&fs::read_to_string(filename).unwrap().split('\n').collect()).unwrap();
        let decrypted_bytes = decrypt_aes_cbc(&ciphertext, &key, &iv.to_vec(), false);
        let plaintext = String::from_utf8_lossy(&decrypted_bytes.as_slice());
        let mut decrypter =
            Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, &key[..], Some(&iv)).unwrap();
        let mut answer = vec![0u8; ciphertext.len() + key.len()];
        decrypter
            .update(&ciphertext[..], answer.as_mut_slice())
            .unwrap();
        let answer = String::from_utf8_lossy(answer.as_slice())
            .trim_end_matches("\u{0}")
            .to_string();
        assert_eq!(plaintext, answer);
    }

    #[test]
    fn test_encrypting_aes_cbc() {
        let input = "Trying to decrypt something else to see if it works."
            .as_bytes()
            .to_vec();
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let iv = [0u8; 16usize].to_vec();
        let ciphertext = encrypt_aes_cbc(&input, &key, &iv);
        let plaintext = decrypt_aes_cbc(&ciphertext, &key, &iv, true);
        let answer = String::from_utf8_lossy(&input.as_slice());
        assert_eq!(String::from_utf8_lossy(plaintext.as_slice()), answer);
    }

    // TODO figure out why this seems to be non-deterministic
    #[test]
    fn test_encryption_oracle() {
        let mut input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .as_bytes()
            .to_vec();
        for _ in 0..100 {
            let (answer, result) = aes_encryption_oracle(&mut input);
            assert_eq!(result, answer);
        }
    }
}
