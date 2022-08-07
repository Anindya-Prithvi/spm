use openssl::hash::{hash, MessageDigest};
use std::{fs, path};

pub fn verify_password(keyhash: &Vec<u8>) -> Result<String, String> {
    println!("Enter Master Password: ");
    let password = match rpassword::read_password() {
        Ok(x) => x,
        Err(e) => return Err(e.to_string()),
    };
    let passwordpadded = format!("{:\x31<32}", password);
    if passwordpadded.len() > 32 {
        println!("Password is too long");
        return Err("Password too long".to_string());
    }
    let passwordhash = match hash(MessageDigest::sha512(), passwordpadded.as_bytes()) {
        Ok(x) => x,
        Err(e) => {
            return Err(e.to_string());
        }
    };

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
    println!(
        "Welcome to Master Password creator\n\
        ## Do not use any %s at the end\n\
        ## Password should be <= 32 characters"
    );
    let password = match rpassword::read_password() {
        Ok(x) => x,
        Err(e) => {
            println!("Key creation failed.\n{}", e);
            return;
        }
    };
    //println!("## Password is {:?}", password);
    let key = format!("{:\x31<32}", password);
    if key.len() > 32 {
        println!("Password is too long");
        return;
    }
    let keyhash = match hash(MessageDigest::sha512(), key.as_bytes()) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    match fs::write(format!("{}/key.txt", basepath.display()), keyhash) {
        Ok(_) => {
            println!("Key creation successful");
        }
        Err(e) => println!("{}", e),
    };
}
