extern crate proc_macro;

mod codec;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use crate::codec::Codec;

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let mut rng = thread_rng();

    let mut codecs = Codec::all();
    codecs.shuffle(&mut rng);

    let (first_codecs, rest) = codecs.split_at(3);
    let (second_codecs, third_codecs) = rest.split_at(2);

    let key1: u8 = rng.gen();
    let key2: u8 = rng.gen();

    let mut data = original_str.as_bytes().to_vec();

    for codec in first_codecs {
        data = codec.encode(&data);
    }
    data = data.iter().map(|&b| b ^ key1).collect();
    for codec in second_codecs {
        data = codec.encode(&data);
    }
    data = data.iter().map(|&b| b ^ key2).collect();
    for codec in third_codecs {
        data = codec.encode(&data);
    }

    let final_encoded = String::from_utf8(data).unwrap();

    let mut decode_logic = Vec::new();
    let data_var = syn::Ident::new("data", proc_macro2::Span::call_site());

    for codec in third_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! { let #data_var: Vec<u8> = #data_var.iter().map(|&b| b ^ #key2).collect(); });
    for codec in second_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! { let #data_var: Vec<u8> = #data_var.iter().map(|&b| b ^ #key1).collect(); });
    for codec in first_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }

    let gen = quote! {
        {
            let mut #data_var = #final_encoded.as_bytes().to_vec();
            #(#decode_logic)*
            String::from_utf8(#data_var).unwrap()
        }
    };

    gen.into()
}