use super::decfuns::read_password;
use super::encfuns::write_password;
use openssl::symm::Cipher;
use std::io::Error;
use std::{fs, io, path};

//unwraps in this files are panics which "should" panic imo

pub fn interact(basepath: &path::PathBuf, keyhash: &Vec<u8>, cipher: &Cipher, iv: &[u8]) {
    println!("1. Read password\n2. Create Password\nEnter 1 or 2: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    match input.trim() {
        "1" => {
            match read_directory(basepath) {
                Ok(_) => {
                    println!("Enter identifying name (domain) of password to read: ");
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).unwrap();
                    read_password(input.trim(), &keyhash, &cipher, iv, &basepath);
                }
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };
        }
        "2" => {
            match fs::read_dir(format!("{}/dnames", basepath.display())) {
                Ok(_) => true,
                Err(_) => {
                    fs::create_dir(format!("{}/dnames", basepath.display())).unwrap();
                    false
                }
            };
            println!("Enter information identifier (domain): ");
            let mut inputdomain = String::new();
            io::stdin().read_line(&mut inputdomain).unwrap();
            println!("Enter information to encrypt (password): ");
            let inputpass = rpassword::read_password().unwrap();
            write_password(
                inputdomain.trim(),
                &inputpass,
                &keyhash,
                &cipher,
                iv,
                &basepath,
            );
        }
        _ => {
            println!("Invalid input");
        }
    }
}

pub fn read_directory(basepath: &path::PathBuf) -> Result<String, Error> {
    let mut passdir = match fs::read_dir(format!("{}/dnames", basepath.display())) {
        Ok(x) => x,
        Err(e) => {
            return Err(e);
        }
    };
    if let Some(x) = passdir.next() {
        println!("--> {}", x.unwrap().file_name().into_string().unwrap());
        for file in passdir {
            println!("--> {}", file.unwrap().file_name().into_string().unwrap());
        }
        return Ok("Success".to_string());
    } else {
        return Err(Error::new(io::ErrorKind::Other, "No passwords saved yet"));
    }
}
