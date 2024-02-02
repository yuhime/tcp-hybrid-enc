use openssl::symm::{encrypt, Cipher};
use rand::Rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha512;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::{env, fs};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() == 1 {
        eprintln!("usage ./program <file>");
        exit(1);
    }
    if !fs::metadata(args[1].to_string()).is_ok() {
        eprintln!("file not found");
        exit(1);
    }
    let file_byte = fs::read(args[1].to_string()).unwrap();

    let mut stream = TcpStream::connect("127.0.0.1:9123").unwrap();

    // get public key (RSA)
    let mut buf = [0; 1024];
    let byte_read = stream.read(&mut buf).unwrap();
    let pub_key = RsaPublicKey::from_public_key_der(&buf[..byte_read]).unwrap();

    // create key for AES encryption
    let mut rng = rand::thread_rng();
    let aes_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let aes_iv: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

    let enc_file_byte =
        encrypt(Cipher::aes_256_cbc(), &aes_key, Some(&aes_iv), &file_byte).unwrap();

    let enc_aes_key = pub_key
        .encrypt(&mut rng, Oaep::new::<Sha512>(), &aes_key)
        .unwrap();

    let enc_aes_iv = pub_key
        .encrypt(&mut rng, Oaep::new::<Sha512>(), &aes_iv)
        .unwrap();

    println!("enc aes key : {}", enc_aes_key.len());
    println!("enc aes iv : {}", enc_aes_iv.len());

    let mut confirm = [0; 4];
    stream.write(&enc_aes_key).unwrap();
    stream.flush().unwrap();
    stream.read(&mut confirm).unwrap();

    stream.write(&enc_aes_iv).unwrap();
    stream.flush().unwrap();
    stream.read(&mut confirm).unwrap();

    stream.write(&enc_file_byte.len().to_be_bytes()).unwrap();
    stream.flush().unwrap();
    stream.read(&mut confirm).unwrap();

    stream.write(&enc_file_byte).unwrap();
    stream.flush().unwrap();
    stream.read(&mut confirm).unwrap();
}
