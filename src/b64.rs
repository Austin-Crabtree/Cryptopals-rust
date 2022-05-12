use base64::DecodeError;

// CryptoPals Set 1 Challenge 1
/// Takes a borrows a Vec of bytes and returns a
/// base64 encoded String
pub fn b64_encode(bytes: &Vec<u8>) -> String {
    base64::encode(bytes)
}

/// Takes a base64 encoded string and returns a
/// Result with either a Vec of bytes or a DecodeError
pub fn b64_decode(encoded: &String) -> Result<Vec<u8>, DecodeError> {
    base64::decode(encoded)
}
