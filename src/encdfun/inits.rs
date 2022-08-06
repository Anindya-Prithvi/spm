use super::decfuns::read_password;
use super::encfuns::write_password;
use openssl::symm::Cipher;
use std::{fs, io, path};

pub fn interact(basepath: &path::PathBuf, keyhash: &Vec<u8>, cipher: &Cipher, iv: &[u8]) {
    println!("1. Read password\n2. Create Password\nEnter 1 or 2: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    match input.trim() {
        "1" => {
            let mut passdir = match fs::read_dir(format!("{}/dnames", basepath.display())) {
                Ok(x) => x,
                Err(_) => {
                    println!("No passwords saved");
                    return;
                }
            };
            if let Some(x) = passdir.next() {
                println!("{}", x.unwrap().file_name().into_string().unwrap());
                for file in passdir {
                    println!("1. {}", file.unwrap().file_name().into_string().unwrap());
                }
            } else {
                println!("No passwords saved");
                return;
            }

            println!("Enter identifying name (domain) of password to read: ");
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            read_password(input.trim(), &keyhash, &cipher, iv, &basepath);
        }
        "2" => {
            match fs::read_dir(format!("{}/dnames", basepath.display())) {
                Ok(_) => true,
                Err(_) => {
                    fs::create_dir(format!("{}/dnames", basepath.display())).unwrap();
                    false
                }
            };
            println!("Enter password identifier (domain): ");
            let mut inputdomain = String::new();
            io::stdin().read_line(&mut inputdomain).unwrap();
            println!("Enter password: ");
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
