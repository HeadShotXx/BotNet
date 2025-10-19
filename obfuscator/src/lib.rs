extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use rand::distributions::Alphanumeric;
use crc32fast::Hasher;

// COCEC.RS
#[derive(Debug, Clone, Copy)]
enum Codec {
    Base36,
    Base45,
    Base58,
    Base85,
    Base91,
    Base122,
}

impl Codec {
    fn all() -> Vec<Self> {
        vec![
            Codec::Base36,
            Codec::Base45,
            Codec::Base58,
            Codec::Base85,
            Codec::Base91,
            Codec::Base122,
        ]
    }

    fn encode(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Codec::Base36 => base36::encode(data).as_bytes().to_vec(),
            Codec::Base45 => base45::encode(data).as_bytes().to_vec(),
            Codec::Base58 => bs58::encode(data).into_string().into_bytes(),
            Codec::Base85 => base85::encode(data).as_bytes().to_vec(),
            Codec::Base91 => base91::slice_encode(data),
            Codec::Base122 => base122_rs::encode(data).as_bytes().to_vec(),
        }
    }

    fn get_decode_logic(&self, data_var: &syn::Ident) -> proc_macro2::TokenStream {
        match self {
            Codec::Base36 => quote! { let #data_var = base36::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base45 => quote! { let #data_var = base45::decode(String::from_utf8_lossy(&#data_var).as_ref()).unwrap(); },
            Codec::Base58 => quote! { let #data_var = bs58::decode(String::from_utf8_lossy(&#data_var).as_ref()).into_vec().unwrap(); },
            Codec::Base85 => quote! { let #data_var = base85::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base91 => quote! { let #data_var = base91::slice_decode(&#data_var); },
            Codec::Base122 => quote! { let #data_var = base122_rs::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
        }
    }
}

// KEY_MANAGEMENT.RS
fn generate_key_fragments(key_size: usize) -> (Vec<u8>, proc_macro2::TokenStream, Vec<syn::Ident>, Vec<syn::Ident>) {
    let mut rng = thread_rng();
    let key: Vec<u8> = (0..key_size).map(|_| rng.gen()).collect();

    let num_fragments = rng.gen_range(2..=8);
    let fragment_size = (key_size + num_fragments - 1) / num_fragments;

    let mut fragments: Vec<Vec<u8>> = Vec::new();
    let mut checksums: Vec<u32> = Vec::new();
    let mut fragment_vars = Vec::new();
    let mut checksum_vars = Vec::new();

    let mut static_defs = Vec::new();

    for i in 0..num_fragments {
        let start = i * fragment_size;
        let end = ((i + 1) * fragment_size).min(key_size);
        if start >= end {
            continue;
        }

        let fragment = &key[start..end];
        let encoded_fragment: Vec<u8> = fragment.iter().map(|b| b.wrapping_add(i as u8)).collect();

        let mut hasher = Hasher::new();
        hasher.update(&encoded_fragment);
        let checksum = hasher.finalize();

        fragments.push(encoded_fragment.clone());
        checksums.push(checksum);

        let var_name_base: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let fragment_var_name = syn::Ident::new(&format!("FRAG_{}", var_name_base), proc_macro2::Span::call_site());
        let checksum_var_name = syn::Ident::new(&format!("CS_{}", var_name_base), proc_macro2::Span::call_site());

        let encoded_fragment_literal = proc_macro2::Literal::byte_string(&encoded_fragment);

        static_defs.push(quote! {
            static #fragment_var_name: &'static [u8] = #encoded_fragment_literal;
            static #checksum_var_name: u32 = #checksum;
        });

        fragment_vars.push(fragment_var_name);
        checksum_vars.push(checksum_var_name);
    }

    let gen = quote! {
        #(#static_defs)*
    };

    (key, gen, fragment_vars, checksum_vars)
}

fn generate_key_reconstruction_logic(
    key_name: &str,
    key_size: usize,
    fragment_vars: &[syn::Ident],
    checksum_vars: &[syn::Ident],
) -> (syn::Ident, proc_macro2::TokenStream) {
    let key_var = syn::Ident::new(key_name, proc_macro2::Span::call_site());
    let mut reconstruction_steps = Vec::new();

    for (i, (fragment_var, checksum_var)) in fragment_vars.iter().zip(checksum_vars.iter()).enumerate() {
        let step = quote! {
            {
                let fragment_data = #fragment_var;
                let expected_checksum = #checksum_var;

                let mut hasher = crc32fast::Hasher::new();
                hasher.update(fragment_data);
                let actual_checksum = hasher.finalize();

                if actual_checksum != expected_checksum {
                    panic!("Checksum mismatch detected! Possible tampering.");
                }

                let decoded_fragment: Vec<u8> = fragment_data.iter().map(|b| b.wrapping_sub(#i as u8)).collect();
                #key_var.extend_from_slice(&decoded_fragment);
            }
        };
        reconstruction_steps.push(step);
    }

    let logic = quote! {
        let mut #key_var = Vec::with_capacity(#key_size);
        #(#reconstruction_steps)*
    };

    (key_var, logic)
}

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

    let (key1_var, key1_recon_logic) = generate_key_reconstruction_logic("reconstructed_key_1", 16, &key1_frag_vars, &key1_checksum_vars);
    let (key2_var, key2_recon_logic) = generate_key_reconstruction_logic("reconstructed_key_2", 16, &key2_frag_vars, &key2_checksum_vars);

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
            use crc32fast::Hasher;
            #key1_defs
            #key2_defs

            #key1_recon_logic
            #key2_recon_logic

            let mut #data_var = #final_encoded.to_vec();

            #(#decode_logic)*

            String::from_utf8(#data_var).unwrap()
        }
    };

    gen.into()
}