extern crate proc_macro;

mod codec;
mod key_obfuscation;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use crate::codec::Codec;
use crate::key_obfuscation::obfuscate as obfuscate_key;

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let mut rng = thread_rng();

    let mut codecs = Codec::all();
    codecs.shuffle(&mut rng);

    let (first_codecs, rest) = codecs.split_at(rng.gen_range(1..4));
    let (second_codecs, third_codecs) = rest.split_at(rng.gen_range(1..3));

    let key1: u8 = rng.gen();
    let key2: u8 = rng.gen();

    let obf_key1 = obfuscate_key(key1);
    let obf_key2 = obfuscate_key(key2);

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

    let final_encoded = proc_macro2::Literal::byte_string(&data);

    let mut decode_logic = Vec::new();
    let data_var = syn::Ident::new("data", proc_macro2::Span::call_site());

    let high1_decode = obf_key1.high_codec.get_decode_logic(&obf_key1.encoded_high, obf_key1.high_rot);
    let low1_decode = obf_key1.low_codec.get_decode_logic(&obf_key1.encoded_low, obf_key1.low_rot);
    let key1_expr = quote! { ((#high1_decode) << 4) | (#low1_decode) };

    let high2_decode = obf_key2.high_codec.get_decode_logic(&obf_key2.encoded_high, obf_key2.high_rot);
    let low2_decode = obf_key2.low_codec.get_decode_logic(&obf_key2.encoded_low, obf_key2.low_rot);
    let key2_expr = quote! { ((#high2_decode) << 4) | (#low2_decode) };

    for codec in third_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! { let #data_var: Vec<u8> = #data_var.iter().map(|&b| b ^ #key2_expr).collect(); });
    for codec in second_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! { let #data_var: Vec<u8> = #data_var.iter().map(|&b| b ^ #key1_expr).collect(); });
    for codec in first_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }

    let gen = quote! {
        {
            let mut #data_var = #final_encoded.to_vec();
            #(#decode_logic)*
            #data_var
        }
    };

    gen.into()
}