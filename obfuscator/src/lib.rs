extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();

    // Encode with base85
    let base85_encoded = base85::encode(original_str.as_bytes());

    // XOR encryption
    let mut rng = thread_rng();
    let key: u8 = rng.gen();
    let xor_encrypted: Vec<u8> = base85_encoded.as_bytes().iter().map(|&b| b ^ key).collect();

    // Encode with base45
    let final_encoded = base45::encode(&xor_encrypted);

    let gen = quote! {
        {
            let encoded = #final_encoded;
            let key = #key;

            // Decode from base45
            let base45_decoded = base45::decode(encoded).unwrap();

            // XOR decryption
            let xor_decrypted: Vec<u8> = base45_decoded.iter().map(|&b| b ^ key).collect();
            let base85_encoded_str = String::from_utf8(xor_decrypted).unwrap();

            // Decode from base85
            let final_decoded_bytes = base85::decode(&base85_encoded_str).unwrap();

            String::from_utf8(final_decoded_bytes).unwrap()
        }
    };

    gen.into()
}