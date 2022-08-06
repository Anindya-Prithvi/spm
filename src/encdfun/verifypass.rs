use openssl::hash::{hash, MessageDigest};
use std::{fs, path};

pub fn verify_password(keyhash: &Vec<u8>) -> Result<String, String> {
    println!("Enter Master Password: ");
    let password = rpassword::read_password().unwrap();
    let passwordpadded = format!("{:\x31<32}", password);
    if passwordpadded.len() > 32 {
        println!("Password is too long");
        return Err("Password too long".to_string());
    }
    let passwordhash = hash(MessageDigest::sha512(), passwordpadded.as_bytes()).unwrap();

    let matched = passwordhash
        .iter()
        .zip(keyhash.iter())
        .fold(true, |acc, (x, y)| acc && (x == y));

    if matched {
        println!("Password verified");
        return Ok(passwordpadded);
    } else {
        return Err("Password incorrect".to_string());
    }
}
pub fn key_creator(basepath: &path::PathBuf) {
    println!("Welcome to Master Password creator");
    println!("## Do not use any %s at the end");
    println!("## Password should be <= 32 characters");
    let password = rpassword::read_password().unwrap();
    //println!("## Password is {:?}", password);
    let key = format!("{:\x31<32}", password);
    if key.len() > 32 {
        println!("Password is too long");
        return;
    }
    fs::write(
        format!("{}/key.txt", basepath.display()),
        hash(MessageDigest::sha512(), key.as_bytes()).unwrap(),
    )
    .unwrap();
    println!("Key creation successful");
}
