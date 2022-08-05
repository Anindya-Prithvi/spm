use openssl::hash::{hash, MessageDigest};
use openssl::symm::{decrypt, encrypt, Cipher};
use std::{fs, io};

fn main() {
    let cipher = Cipher::aes_128_cbc();
    let iv = b"watashiwa kyojin"; // or change acc your needs, doesn't matter
    println!("Welcome to post pwn clarity");
    let keyhash = loop {
        let val = match fs::read("key.txt") {
            Ok(x) => Some(x),
            Err(e) => {
                println!("key doesn't exist yet");
                None
            }
        };

        if let Some(x) = val {
            break x;
        } else {
            keycreator();
        }
    };
    println!("keyhash: {:?}", keyhash);
    verifyPassword(keyhash).unwrap();
    // add function to add passwords
}

fn verifyPassword(keyhash: Vec<u8>) -> Result<(), String> {
    let password = rpassword::read_password().unwrap();
    let passwordpadded = format!("{:x<16}", password);
    if passwordpadded.len() > 16 {
        println!("Password is too long");
        return Err("Password too long".to_string());
    }
    let passwordhash = hash(MessageDigest::sha512(), passwordpadded.as_bytes()).unwrap();
    let mut matched:bool = true;
    passwordhash.iter().zip(keyhash.iter()).for_each(|(x, y)| {
        matched = matched && (x == y);
    });
    if matched {
        println!("Password verified");
        return Ok(());
    } else {
        return Err("Password incorrect".to_string());
    }
}

fn keycreator() {
    println!("Welcome to key creator");
    println!("## Do not use any %s at the end");
    println!("## Password should be smaller than 16 characters");
    let password = rpassword::read_password().unwrap();
    println!("## Password is {:?}", password);
    let key = format!("{:x<16}", password);
    if key.len() > 16 {
        println!("Password is too long");
        return;
    }
    fs::write("key.txt", hash(MessageDigest::sha512(), key.as_bytes()).unwrap()).unwrap();
    println!("Key creation successful");
}

fn dmain() {

}

fn decrypter(data: &Vec<u8>, key: &[u8], iv: &[u8]) {
    let cipher = Cipher::aes_128_cbc();
    let ciphertext = decrypt(cipher, key, Some(iv), data).unwrap();
    println!("{}", String::from_utf8(ciphertext).expect("Invalid UTF-8"));
}
