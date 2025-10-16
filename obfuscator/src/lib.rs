extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let mut rng = thread_rng();

    // Encryption Chain
    let key1: u8 = rng.gen();
    let key2: u8 = rng.gen();

    // 1. base85
    let base85_encoded = base85::encode(original_str.as_bytes());

    // 2. xor1
    let xor1_encrypted: Vec<u8> = base85_encoded.as_bytes().iter().map(|&b| b ^ key1).collect();

    // 3. base45
    let base45_encoded = base45::encode(&xor1_encrypted);

    // 4. base36
    let base36_encoded = base36::encode(base45_encoded.as_bytes());

    // 5. xor2
    let xor2_encrypted: Vec<u8> = base36_encoded.as_bytes().iter().map(|&b| b ^ key2).collect();

    // 6. base91
    let base91_encoded = base91::slice_encode(&xor2_encrypted);

    // 7. base122
    let base122_encoded = base122_rs::encode(&base91_encoded);

    // 8. base58
    let final_encoded = bs58::encode(&base122_encoded).into_string();

    // Decryption Chain (in reverse)
    let gen = quote! {
        {
            let encoded = #final_encoded;
            let key1 = #key1;
            let key2 = #key2;

            // 8. base58 decode
            let base58_decoded = bs58::decode(encoded).into_vec().unwrap();

            // 7. base122 decode
            let base122_decoded = base122_rs::decode(&String::from_utf8_lossy(&base58_decoded)).unwrap();

            // 6. base91 decode
            let base91_decoded = base91::slice_decode(&base122_decoded);

            // 5. xor2 decrypt
            let xor2_decrypted: Vec<u8> = base91_decoded.iter().map(|&b| b ^ key2).collect();
            let base36_encoded_str = String::from_utf8(xor2_decrypted).unwrap();

            // 4. base36 decode
            let base36_decoded = base36::decode(&base36_encoded_str).unwrap();
            let base45_encoded_str = String::from_utf8(base36_decoded).unwrap();

            // 3. base45 decode
            let base45_decoded = base45::decode(&base45_encoded_str).unwrap();

            // 2. xor1 decrypt
            let xor1_decrypted: Vec<u8> = base45_decoded.iter().map(|&b| b ^ key1).collect();
            let base85_encoded_str = String::from_utf8(xor1_decrypted).unwrap();

            // 1. base85 decode
            let final_decoded_bytes = base85::decode(&base85_encoded_str).unwrap();

            String::from_utf8(final_decoded_bytes).unwrap()
        }
    };

    gen.into()
}