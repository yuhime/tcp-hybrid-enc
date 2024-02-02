# Tcp-hybrid-enc
A simple hybrid encrypted file sharer: asymmetric and symmetric encryption.
One-way (alice -> bob)
## Run
```
git clone https://github.com/yuhime/rust-tcp-rsa && cd rust-tcp-rsa
```
Open two windows in the terminal: one for bob and one for alice.
```bash
# bob
cargo run --example bob

#alice
cargo run --example alice <PATH-TO-FILE>
```
Bob acts as the server so be sure to start him first.