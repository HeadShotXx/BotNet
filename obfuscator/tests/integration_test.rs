use obfuscator::obfuscate;

#[test]
fn test_obfuscation_simple() {
    let original = "Hello, world!";
    let obfuscated = obfuscate!("Hello, world!");
    assert_eq!(obfuscated, original);
}

#[test]
fn test_obfuscation_long() {
    let original = "This is a much longer string to test the obfuscation with, ensuring that it handles different lengths and characters correctly.";
    let obfuscated = obfuscate!("This is a much longer string to test the obfuscation with, ensuring that it handles different lengths and characters correctly.");
    assert_eq!(obfuscated, original);
}

#[test]
fn test_obfuscation_special_chars() {
    let original = "!@#$%^&*()_+-=[]{}|;':,./<>?`~";
    let obfuscated = obfuscate!("!@#$%^&*()_+-=[]{}|;':,./<>?`~");
    assert_eq!(obfuscated, original);
}

#[test]
fn test_obfuscation_empty() {
    let original = "";
    let obfuscated = obfuscate!("");
    assert_eq!(obfuscated, original);
}