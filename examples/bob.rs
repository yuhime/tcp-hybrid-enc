use openssl::symm::{decrypt, Cipher};
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha512;
use std::fs::File;
use std::io::Read;
use std::{io::Write, net::TcpListener};
use std::{thread, vec};

fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate priv key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let listener = TcpListener::bind("127.0.0.1:9123").unwrap();
    println!("listening started");

    for stream in listener.incoming() {
        let priv_key_clone = priv_key.clone();
        let pub_key_clone = pub_key.clone();

        thread::spawn(move || {
            let mut stream = stream.unwrap();
            stream
                .write(pub_key_clone.to_public_key_der().unwrap().as_bytes())
                .unwrap();
            println!(
                "client {} connected. Ready for file",
                stream.peer_addr().unwrap()
            );

            let mut buf = [0; 1024];
            let mut bytes_read = stream.read(&mut buf).unwrap();

            stream.write(&(i32::to_be_bytes(0))).unwrap();
            stream.flush().unwrap();

            println!("{}", bytes_read);
            let aes_key = priv_key_clone
                .decrypt(Oaep::new::<Sha512>(), &buf[..bytes_read])
                .unwrap();

            bytes_read = stream.read(&mut buf).unwrap();

            stream.write(&(i32::to_be_bytes(0))).unwrap();
            stream.flush().unwrap();

            let aes_iv = priv_key_clone
                .decrypt(Oaep::new::<Sha512>(), &buf[..bytes_read])
                .unwrap();

            let mut file_size_buf = [0; 8];
            stream.read_exact(&mut file_size_buf).unwrap();

            stream.write(&(i32::to_be_bytes(0))).unwrap();
            stream.flush().unwrap();

            let mut enc_file_byte_buf = vec![0; u64::from_be_bytes(file_size_buf) as usize];
            stream.read_exact(&mut enc_file_byte_buf).unwrap();

            let dec_file_byte = decrypt(
                Cipher::aes_256_cbc(),
                &aes_key,
                Some(&aes_iv),
                &enc_file_byte_buf,
            )
            .unwrap();

            let mut file = File::create("test_output_dec").unwrap();
            file.write(&dec_file_byte).unwrap();
            file.flush().unwrap();

            let mut file = File::create("test_output_enc").unwrap();
            file.write(&enc_file_byte_buf).unwrap();
            file.flush().unwrap();
        });
    }
}
