use obfuscator::obfuscate;

#[test]
fn test_obfuscation() {
    let obfuscated = obfuscate!("Thisisateststring");
    assert_eq!(obfuscated, "Thisisateststring".as_bytes());
}