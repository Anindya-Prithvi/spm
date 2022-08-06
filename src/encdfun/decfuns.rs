use openssl::symm::{decrypt, Cipher};
use std::{fs, path};

use super::verifypass::verify_password;

pub fn decrypter(data: &Vec<u8>, key: &[u8], cipher: &Cipher, iv: &[u8]) -> String {
    let ciphertext = decrypt(*cipher, key, Some(iv), data).unwrap();
    return String::from_utf8(ciphertext).expect("Invalid UTF-8 | Different encryption key");
}
pub fn read_password(
    name: &str,
    keyhash: &Vec<u8>,
    cipher: &Cipher,
    iv: &[u8],
    basepath: &path::PathBuf,
) {
    let unlockpass = verify_password(keyhash).unwrap();
    println!("Trying to read {}/dnames/{}", basepath.display(), name);
    //decrypt here
    let passfile = fs::read(format!("{}/dnames/{}", basepath.display(), name)).unwrap();
    let pass = decrypter(&passfile, unlockpass.as_bytes(), cipher, iv);
    println!("Password for {} is: {}", name, pass);
}
