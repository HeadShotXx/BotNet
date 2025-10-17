use obfuscator::obfuscate;

fn main() {
    let my_secret_string = obfuscate!("Hello, this is a secret message!");
    println!("Decrypted string: {}", my_secret_string);
}