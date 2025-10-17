use obfuscator::obfuscate;

fn main() {
    let my_secret_string = obfuscate!("Hello, this is a secret message!");
    println!("Decrypted string: {}", String::from_utf8_lossy(&my_secret_string));
}