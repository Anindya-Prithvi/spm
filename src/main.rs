use encdfun::inits;
use encdfun::inits::read_directory;
use encdfun::verifypass::key_creator;
use encdfun::{decfuns::read_password, encfuns::write_password};
use openssl::symm::Cipher;
use std::{env, fs, io, path};

pub mod encdfun;

fn main() {
    let mut basepath: path::PathBuf = env::current_exe().unwrap(); //necessary panic
    basepath.pop();
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
    let totalargs = args.len();
    if totalargs > 1 {
        match args[1].as_str() {
            "--list" | "-l" => {
                match read_directory(&basepath) {
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
            "--read" | "-r" => {
                println!("Reading mode");
                if totalargs != 3 {
                    println!("Invalid syntax: Correction --> spm --read <identifier>");
                    return;
                }
                read_password(args[2].as_str(), &keyhash, &cipher, iv, &basepath);
                return;
            }
            "--write" | "-w" => {
                println!("Writing mode. Spaces in password disallowed");
                if totalargs != 4 {
                    println!("Invalid syntax: Correction --> spm --write <identifier> <password>");
                    return;
                }
                write_password(args[2].as_str(), &args[3], &keyhash, &cipher, iv, &basepath);
                return;
            }
            "--help" | "-h" => {
                println!(
                    "\
                    Usage: To view help menu\n\
                    \tspm -h\n\
                    \tspm --help\n\
                    Usage: To list all identifiers\n\
                    \tspm -l\n\
                    \tspm --list\n\
                    Usage: To read directly (non interactive)\n\
                    \tspm --read <identifier>\n\
                    \tspm -r <identifier>\n\
                    Usage: To write directly (non interactive)\n\
                    \tspm --write <identifier> <password>\n\
                    \tspm -w <identifier> <password>\n\
                    For additional security, you can delete {}/key.txt\n\
                    but be SURE to keep the creation(Master) password same",
                    basepath.display()
                );
            }
            _ => {
                println!("Invalid options\n Falling back to Interactive mode:");
                loop {
                    inits::interact(&basepath, &keyhash, &cipher, iv);
                }
            }
        }
    } else {
        println!("Welcome to interactive mode");
        loop {
            inits::interact(&basepath, &keyhash, &cipher, iv);
        }
    }
}
