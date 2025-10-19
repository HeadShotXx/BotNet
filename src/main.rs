use my_lib::get_secret_message;

fn main() {
    let my_secret_string = get_secret_message();
    println!("Decrypted string from my_lib: {}", my_secret_string);
}