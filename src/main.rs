use encdfun::inits;
use encdfun::verifypass::key_creator;
use openssl::symm::Cipher;
use std::{env, fs, path};
pub mod encdfun;

fn main() {
    let mut basepath: path::PathBuf = env::current_exe().unwrap();
    basepath.pop();
    println!("{}", basepath.display());
    let cipher = Cipher::aes_256_cbc();
    let iv = b"watashiwa kyojin"; // or change acc your needs, doesn't matter
    println!("Welcome to post pwn clarity");
    let keyhash = loop {
        let val = match fs::read(format!("{}/key.txt", basepath.display())) {
            Ok(x) => Some(x),
            Err(_) => {
                println!("key doesn't exist yet");
                None
            }
        };

        if let Some(x) = val {
            break x;
        } else {
            key_creator(&basepath);
        }
    };

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "read" => {
                println!("Reading mode");
            }
            "write" => {
                println!("Writing mode");
            }
            _ => {
                println!("Interactive mode --xxxx--");
                loop {
                    inits::interact(&basepath, &keyhash, &cipher, iv);
                }
            }
        }
        println!("{:?}", args);
    }
}
