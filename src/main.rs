use openssl::hash::{hash, MessageDigest};
use openssl::symm::{decrypt, encrypt, Cipher};
use std::{fs, io};

fn main() {
    let cipher = Cipher::aes_256_cbc();
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
    // println!("keyhash: {:?}", keyhash);
    // verifyPassword(keyhash).unwrap();
    println!("## Entering infinite loop");
    // add function to add passwords
    loop {
        println!("1. Read password\n2. Create Password\nEnter 1 or 2: ");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim() {
            "1" => {
                let passdir =
                    match fs::read_dir("./dnames") {
                        Ok(x) => x,
                        Err(e) => {
                            println!("No passwords saved");
                            continue;
                        },
                    };
                let mut totalpass = 1;
                for file in passdir {
                    println!("1. {}", file.unwrap().file_name().into_string().unwrap());
                    totalpass += 1;
                }
                if totalpass == 1 {
                    println!("No passwords saved");
                    continue;
                }

                println!("Enter identifying name (domain) of password to read: ");
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                readpassword(input.trim(), &keyhash, cipher, iv);
            }
            "2" => {
                let success = match fs::read_dir("./dnames") {
                    Ok(x) => true,
                    Err(e) => {
                        fs::create_dir("./dnames").unwrap();
                        false
                    }
                };
                println!("Enter password identifier (domain): ");
                let mut inputdomain = String::new();
                io::stdin().read_line(&mut inputdomain).unwrap();
                println!("Enter password: ");
                let inputpass = rpassword::read_password().unwrap();
                writepassword(inputdomain.trim(), inputpass, &keyhash, cipher, iv);
            }
            _ => {
                println!("Invalid input");
            }
        }
    }
}

fn readpassword(name: &str, keyhash: &Vec<u8>, cipher: Cipher, iv: &[u8]) {
    let unlockpass = verifyPassword(keyhash).unwrap();
    println!("Trying to read ./dnames/{}", name);
    //decrypt here
    let passfile = fs::read(format!("./dnames/{}", name)).unwrap();
    let pass = decrypter(&passfile, unlockpass.as_bytes(), cipher, iv);
    println!("Password for {} is: {}", name, pass);
}

fn writepassword(name: &str, passsave: String, keyhash: &Vec<u8>, cipher: Cipher, iv: &[u8]) {
    let unlockpass = verifyPassword(keyhash).unwrap();
    //encrypt here
    let enc = encrypter(passsave.as_bytes(), unlockpass.as_bytes(), cipher, iv);
    fs::write(format!("./dnames/{}", name), enc).unwrap();
    println!("Written to ./dnames/{}", name);
}

fn verifyPassword(keyhash: &Vec<u8>) -> Result<String, String> {
    println!("Enter password: ");
    let password = rpassword::read_password().unwrap();
    let passwordpadded = format!("{:\x31<32}", password);
    if passwordpadded.len() > 32 {
        println!("Password is too long");
        return Err("Password too long".to_string());
    }
    let passwordhash = hash(MessageDigest::sha512(), passwordpadded.as_bytes()).unwrap();
    let mut matched: bool = true;
    passwordhash.iter().zip(keyhash.iter()).for_each(|(x, y)| {
        matched = matched && (x == y);
    });
    if matched {
        println!("Password verified");
        return Ok(passwordpadded);
    } else {
        return Err("Password incorrect".to_string());
    }
}

fn keycreator() {
    println!("Welcome to key creator");
    println!("## Do not use any %s at the end");
    println!("## Password should be smaller than 32 characters");
    let password = rpassword::read_password().unwrap();
    //println!("## Password is {:?}", password);
    let key = format!("{:\x31<32}", password);
    if key.len() > 32 {
        println!("Password is too long");
        return;
    }
    fs::write(
        "key.txt",
        hash(MessageDigest::sha512(), key.as_bytes()).unwrap(),
    )
    .unwrap();
    println!("Key creation successful");
}

fn decrypter(data: &Vec<u8>, key: &[u8], cipher: Cipher, iv: &[u8]) -> String{
    let ciphertext = decrypt(cipher, key, Some(iv), data).unwrap();
    return String::from_utf8(ciphertext).expect("Invalid UTF-8 | Different encryption key");
}

fn encrypter(data: &[u8], key: &[u8], cipher: Cipher, iv: &[u8]) -> Vec<u8> {
    return encrypt(cipher, key, Some(iv), data).unwrap();
}
