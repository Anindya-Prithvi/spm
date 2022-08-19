use clap::{Arg, Command};
use encdfun::inits;
use encdfun::inits::{init_dir, read_directory};
use encdfun::verifypass::key_creator;
use encdfun::{decfuns::read_password, encfuns::write_password};
use openssl::symm::Cipher;
use std::io::ErrorKind;
use std::{env, fs, path};

pub mod encdfun;

fn main() {
    let mut basepath: path::PathBuf = env::current_exe().unwrap(); //necessary panic
    basepath.pop(); // fix permission issues, but that may platform restrict

    match init_dir(&basepath) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() != ErrorKind::AlreadyExists {
                println!("Attempted to create at {}", basepath.display());
                return;
            }
        }
    }

    let cipher = Cipher::aes_256_cbc();
    let iv = b"watashiwa kyojin"; // or change acc your needs, doesn't matter

    // login keys
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

    let cli_opts = Command::new("Safe Password Manager")
        .about("Yet another password manager, but with CLI made in rust.")
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .takes_value(false)
                .help("Lists all available password identifiers"),
        )
        .arg(
            Arg::new("read")
                .short('r')
                .long("read")
                .takes_value(true)
                .help("print a password given file")
                .value_name("IDENTIFIER"),
        )
        .arg(
            Arg::new("write")
                .short('w')
                .long("write")
                .takes_value(true)
                .help(
                    "writes a password on the disk [encrypted]. \
                Value of password accepted while running the program.",
                )
                .value_name("IDENTIFIER"),
        )
        .after_help(
            "Longer explanation to appear after the options when \
                 displaying the help information from --help or -h",
        )
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .get_matches();

    if cli_opts.args_present() {
        match cli_opts.try_get_one::<String>("read") {
            Ok(x) => {
                if x != None {
                    read_password(x.unwrap(), &keyhash, &cipher, iv, &basepath);
                }
            }
            Err(_) => (),
        }
        match cli_opts.try_get_one::<String>("write") {
            Ok(x) => {
                if x != None {
                    println!("Enter the password you want to save:");
                    let savpass = rpassword::read_password().unwrap();
                    write_password(x.unwrap(), &savpass, &keyhash, &cipher, iv, &basepath);
                }
            }
            Err(_) => (),
        }
        if cli_opts.contains_id("list") {
            match read_directory(&basepath) {
                Ok(_) => {
                    return;
                }
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };
        }
    } else {
        println!("Welcome to interactive mode");
        loop {
            inits::interact(&basepath, &keyhash, &cipher, iv);
        }
    }
}
