use openssl::symm::{encrypt, Cipher};
use std::{fs, path};

use super::verifypass::verify_password;

pub fn encrypter(data: &[u8], key: &[u8], cipher: &Cipher, iv: &[u8]) -> Vec<u8> {
    return encrypt(*cipher, key, Some(iv), data).unwrap();
}

pub fn write_password(
    name: &str,
    passsave: &String,
    keyhash: &Vec<u8>,
    cipher: &Cipher,
    iv: &[u8],
    basepath: &path::PathBuf,
) {
    let unlockpass = verify_password(keyhash).unwrap();
    //encrypt here
    let enc = encrypter(passsave.as_bytes(), unlockpass.as_bytes(), cipher, iv);
    fs::write(format!("{}/dnames/{}", basepath.display(), name), enc).unwrap();
    println!("Written to {}/dnames/{}", basepath.display(), name);
}
