use obfuscator::obfuscate;

#[test]
fn test_obfuscation() {
    let obfuscated = obfuscate!("This is a test string.");
    assert_eq!(obfuscated, "This is a test string.");
}