use openssl::symm::{decrypt, Cipher};
use std::{fs, path};

use super::verifypass::verify_password;

pub fn decrypter(data: &Vec<u8>, key: &[u8], cipher: &Cipher, iv: &[u8]) -> Result<String, String> {
    let ciphertext = match decrypt(*cipher, key, Some(iv), data) {
        Ok(x) => x,
        Err(_) => {
            return Err("Failed to decrypt".to_string());
        }
    };
    return match String::from_utf8(ciphertext) {
        Ok(x) => Ok(x),
        Err(e) => Err(e.to_string()),
    };
}
pub fn read_password(
    name: &str,
    keyhash: &Vec<u8>,
    cipher: &Cipher,
    iv: &[u8],
    basepath: &path::PathBuf,
) {
    let unlockpass = match verify_password(keyhash) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    println!("Trying to read {}/dnames/{}", basepath.display(), name);
    //decrypt here
    let passfile = match fs::read(format!("{}/dnames/{}", basepath.display(), name)) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e.to_string());
            return;
        }
    };
    match decrypter(&passfile, unlockpass.as_bytes(), cipher, iv) {
        Ok(x) => {
            println!("Information in {} is: {}", name, x);
        }
        Err(e) => {
            println!("{}", e);
        }
    };
}
