use obfuscator::obfuscate;

pub fn get_secret_message() -> String {
    obfuscate!("This is a secret message from my_lib!").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let message = get_secret_message();
        assert_eq!(message, "This is a secret message from my_lib!");
    }
}
