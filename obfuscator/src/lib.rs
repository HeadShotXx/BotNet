extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let original_bytes = original_str.as_bytes();

    let mut rng = thread_rng();
    let key: u8 = rng.gen();

    let mut xor_encrypted = Vec::with_capacity(original_bytes.len());
    for &byte in original_bytes {
        xor_encrypted.push(byte ^ key);
    }

    let base85_encoded = base85::encode(&xor_encrypted);

    let gen = quote! {
        {
            let encoded = #base85_encoded;
            let decoded = base85::decode(encoded).unwrap();
            let mut decrypted = Vec::with_capacity(decoded.len());
            let key = #key;
            for &byte in &decoded {
                decrypted.push(byte ^ key);
            }
            String::from_utf8(decrypted).unwrap()
        }
    };

    gen.into()
}