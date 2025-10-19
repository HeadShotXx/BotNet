extern crate proc_macro;

mod codec;
mod key_management;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use crate::codec::Codec;
use crate::key_management::{generate_key_fragments, generate_key_reconstruction_logic};

#[proc_macro]
pub fn obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let mut rng = thread_rng();

    let mut codecs = Codec::all();
    codecs.shuffle(&mut rng);

    let (first_codecs, rest) = codecs.split_at(rng.gen_range(1..=3));
    let (second_codecs, third_codecs) = rest.split_at(rng.gen_range(1..=2));

    let (key1, key1_defs, key1_frag_vars, key1_checksum_vars) = generate_key_fragments(16);
    let (key2, key2_defs, key2_frag_vars, key2_checksum_vars) = generate_key_fragments(16);

    let mut data = original_str.as_bytes().to_vec();

    for codec in first_codecs {
        data = codec.encode(&data);
    }
    data = data.iter().zip(key1.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
    for codec in second_codecs {
        data = codec.encode(&data);
    }
    data = data.iter().zip(key2.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
    for codec in third_codecs {
        data = codec.encode(&data);
    }

    let final_encoded = proc_macro2::Literal::byte_string(&data);

    let mut decode_logic = Vec::new();
    let data_var = syn::Ident::new("data", proc_macro2::Span::call_site());

    let (key1_var, key1_recon_logic) = generate_key_reconstruction_logic(16, &key1_frag_vars, &key1_checksum_vars);
    let (key2_var, key2_recon_logic) = generate_key_reconstruction_logic(16, &key2_frag_vars, &key2_checksum_vars);

    for codec in third_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! {
        let #data_var: Vec<u8> = #data_var.iter().zip(#key2_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key2_var.zeroize();
    });
    for codec in second_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }
    decode_logic.push(quote! {
        let #data_var: Vec<u8> = #data_var.iter().zip(#key1_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key1_var.zeroize();
    });
    for codec in first_codecs.iter().rev() {
        decode_logic.push(codec.get_decode_logic(&data_var));
    }

    let gen = quote! {
        {
            use zeroize::Zeroize;
            #key1_defs
            #key2_defs

            let mut #data_var = #final_encoded.to_vec();

            #key2_recon_logic
            #key1_recon_logic

            #(#decode_logic)*

            String::from_utf8(#data_var).unwrap()
        }
    };

    gen.into()
}