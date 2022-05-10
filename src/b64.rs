extern crate base64;

use base64::DecodeError;

pub fn b64_encode(bytes: &Vec<u8>) -> String {
    base64::encode(bytes)
}

pub fn b64_decode(encoded: String) -> Result<Vec<u8>, DecodeError >{
    base64::decode(encoded)
}
