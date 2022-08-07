use openssl::{
    error::ErrorStack,
    symm::{encrypt, Cipher},
};
use std::{fs, path};

use super::verifypass::verify_password;

pub fn encrypter(
    data: &[u8],
    key: &[u8],
    cipher: &Cipher,
    iv: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    return encrypt(*cipher, key, Some(iv), data);
}

pub fn write_password(
    name: &str,
    passsave: &String,
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
    //encrypt here
    let enc = match encrypter(passsave.as_bytes(), unlockpass.as_bytes(), cipher, iv) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e.to_string());
            return;
        }
    };
    match fs::write(format!("{}/dnames/{}", basepath.display(), name), enc) {
        Ok(_) => {
            println!("Written to {}/dnames/{}", basepath.display(), name);
        }
        Err(e) => {
            println!("{}", e.to_string());
        }
    };
}
