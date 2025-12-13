extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr, ItemFn, Meta, Lit, Expr, ExprLit};
use syn::visit_mut::{self, VisitMut};
use syn::punctuated::Punctuated;
use syn::parse::Parser;
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
            Codec::Base36 => quote! { #data_var = base36::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base45 => quote! { #data_var = base45::decode(String::from_utf8_lossy(&#data_var).as_ref()).unwrap(); },
            Codec::Base58 => quote! { #data_var = bs58::decode(String::from_utf8_lossy(&#data_var).as_ref()).into_vec().unwrap(); },
            Codec::Base85 => quote! { #data_var = base85::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base91 => quote! { #data_var = base91::slice_decode(&#data_var); },
            Codec::Base122 => quote! { #data_var = base122_rs::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
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
pub fn obfuscate_string(input: TokenStream) -> TokenStream {
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

    let data_var = syn::Ident::new("data", proc_macro2::Span::call_site());

    let (key1_var, key1_recon_logic) = generate_key_reconstruction_logic("reconstructed_key_1", 16, &key1_frag_vars, &key1_checksum_vars);
    let (key2_var, key2_recon_logic) = generate_key_reconstruction_logic("reconstructed_key_2", 16, &key2_frag_vars, &key2_checksum_vars);

    // Create a list of all decoding operations.
    // Create a list of all decoding operations.
    let mut decoding_ops = Vec::new();
    for codec in third_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }
    decoding_ops.push(quote! {
        #data_var = #data_var.iter().zip(#key2_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key2_var.zeroize();
    });
    for codec in second_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }
    decoding_ops.push(quote! {
        #data_var = #data_var.iter().zip(#key1_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key1_var.zeroize();
    });
    for codec in first_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }

    // Generate randomized state machine.
    let num_ops = decoding_ops.len();
    let mut states: Vec<u32> = (0..num_ops as u32).collect();
    states.shuffle(&mut rng);
    let initial_state = states[0];

    let mut state_machine_arms = Vec::new();
    for i in 0..num_ops {
        let current_state = states[i];
        let next_state = if i + 1 < num_ops { states[i+1] } else { 999 }; // 999 is the exit state.
        let op = &decoding_ops[i];
        state_machine_arms.push(quote! {
            #current_state => {
                #op
                state = #next_state;
            }
        });
    }
    // Add exit state.
    state_machine_arms.push(quote! { 999 => break, });
    // Add junk states.
    for _ in 0..5 {
        let junk_state: u32 = rng.gen_range(1000..=2000);
        state_machine_arms.push(quote! { #junk_state => { /* unreachable */ }, });
    }
    state_machine_arms.shuffle(&mut rng);


    let gen = quote! {
        {
            use zeroize::Zeroize;
            use crc32fast::Hasher;
            #key1_defs
            #key2_defs

            #key1_recon_logic
            #key2_recon_logic

            let mut #data_var = #final_encoded.to_vec();

            let mut state = #initial_state;
            loop {
                match state {
                    #(#state_machine_arms)*
                    _ => { /* Default case, can be used for anti-tampering */ }
                }
            }

            String::from_utf8(#data_var).unwrap()
        }
    };

    gen.into()
}

fn apply_main_obfuscation(mut main_fn: ItemFn) -> (proc_macro2::TokenStream, ItemFn) {
    if main_fn.sig.ident != "main" {
        panic!("The main obfuscation can only be used on the main function");
    }

    let mut rng = thread_rng();
    let random_part: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(20)
        .collect();
    let random_fn_name = format!("obf_{}", random_part);
    let random_fn_ident = syn::Ident::new(&random_fn_name, main_fn.sig.ident.span());

    let main_fn_body = main_fn.block;

    let new_fn = quote! {
        fn #random_fn_ident() {
            #main_fn_body
        }
    };

    let new_main_body = quote! {
        {
            #random_fn_ident();
        }
    };

    let new_main_body_tokens: TokenStream = new_main_body.into();
    main_fn.block = syn::parse(new_main_body_tokens).expect("Failed to parse new main body");

    (new_fn, main_fn)
}

#[derive(Default)]
struct ObfuscatorArgs {
    fonk_len: Option<u64>,
    garbage: bool,
    main: bool,
    inline: bool,
    control_f: bool,
}

impl ObfuscatorArgs {
    fn from_attrs(attrs: &[Meta]) -> Self {
        let mut args = Self::default();
        for attr in attrs {
            if let Meta::NameValue(nv) = attr {
                if nv.path.is_ident("fonk_len") {
                    if let Expr::Lit(ExprLit { lit: Lit::Int(lit_int), .. }) = &nv.value {
                        args.fonk_len = lit_int.base10_parse().ok();
                    }
                } else if nv.path.is_ident("garbage") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.garbage = lit_bool.value;
                    }
                } else if nv.path.is_ident("main") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.main = lit_bool.value;
                    }
                } else if nv.path.is_ident("inline") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.inline = lit_bool.value;
                    }
                } else if nv.path.is_ident("control_f") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.control_f = lit_bool.value;
                    }
                }
            }
        }
        args
    }
}

#[proc_macro_attribute]
pub fn obfuscate(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = Punctuated::<Meta, syn::Token![,]>::parse_terminated.parse(attr).unwrap();
    let args = ObfuscatorArgs::from_attrs(&attrs.into_iter().collect::<Vec<_>>());
    let mut subject_fn = parse_macro_input!(item as ItemFn);

    let mut output = quote! {};

    if args.main {
        let (new_fn, modified_main) = apply_main_obfuscation(subject_fn.clone());
        output.extend(new_fn);
        subject_fn = modified_main;
    }

    if args.garbage {
        let fonk_len = args.fonk_len.unwrap_or(3);
        subject_fn = apply_junk_obfuscation(subject_fn, fonk_len);
    }

    if args.inline {
        let inline_attr: syn::Attribute = syn::parse_quote! { #[inline] };
        subject_fn.attrs.push(inline_attr);
    }

    if args.control_f {
        let mut visitor = ControlFlowObfuscator;
        visitor.visit_item_fn_mut(&mut subject_fn);
    }

    output.extend(quote! { #subject_fn });
    output.into()
}

struct ControlFlowObfuscator;

impl VisitMut for ControlFlowObfuscator {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        if let Expr::If(if_expr) = expr {
            let mut conditions_and_blocks = vec![];
            let mut final_else_block = None;
            let mut current_if = if_expr.clone();

            // 1. Deconstruct the entire if-else-if chain into a flat list.
            loop {
                let cond = *current_if.cond;
                let then_block = current_if.then_branch;
                conditions_and_blocks.push((cond, then_block));

                if let Some((_, else_branch)) = current_if.else_branch {
                    if let Expr::If(next_if) = *else_branch {
                        current_if = next_if;
                    } else {
                        if let Expr::Block(expr_block) = *else_branch {
                            final_else_block = Some(expr_block.block);
                        } else {
                            // Handle cases like `else { some_expression }`
                            let new_block = syn::parse_quote!({ #else_branch });
                            final_else_block = Some(new_block);
                        }
                        break;
                    }
                } else {
                    break;
                }
            }

            // 2. Recurse into the collected parts to obfuscate nested ifs.
            for (cond, block) in &mut conditions_and_blocks {
                self.visit_expr_mut(cond);
                self.visit_block_mut(block);
            }
            if let Some(else_block) = &mut final_else_block {
                self.visit_block_mut(else_block);
            }

            // 3. Rebuild the logic as a single, flattened match expression with randomization.
            let mut rng = thread_rng();
            let mut arms = Vec::new();
            for (cond, block) in conditions_and_blocks {
                arms.push(quote! { _ if #cond => #block });
            }

            // Add junk arms that can never be reached.
            let num_junk_arms = rng.gen_range(2..=5);
            for _ in 0..num_junk_arms {
                let random_u32: u32 = rng.gen();
                arms.push(quote! { _ if false && #random_u32 == 0 => {} });
            }

            // Shuffle the arms to obscure the original order.
            arms.shuffle(&mut rng);

            let final_arm = if let Some(else_block) = final_else_block {
                quote! { _ => #else_block }
            } else {
                quote! { _ => {} }
            };

            let match_expr_tokens = quote! {
                match () {
                    #(#arms,)*
                    #final_arm,
                }
            };

            if let Ok(new_match_expr) = syn::parse2(match_expr_tokens) {
                *expr = new_match_expr;
            }
            // If parsing fails, leave the original expression untouched.
            return;
        }

        // Default traversal for all other expression types.
        visit_mut::visit_expr_mut(self, expr);
    }
}


fn apply_junk_obfuscation(mut subject_fn: ItemFn, fonk_len: u64) -> ItemFn {
    let mut rng = thread_rng();

    // Generate a random number of junk statements
    let num_junk_statements = rng.gen_range(5..=15);
    let mut junk_statements = Vec::new();

    for _ in 0..num_junk_statements {
        let random_part: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(10)
            .collect();
        let var_name = format!("_{}", random_part);
        let var_ident = syn::Ident::new(&var_name, proc_macro2::Span::call_site());
        let random_val: u32 = rng.gen();

        let junk_statement = quote! {
            let #var_ident = #random_val;
        };
        junk_statements.push(junk_statement);
    }

    // Wrap junk code in a complex loop
    let loop_iterations = fonk_len;
    let loop_counter_name: String = format!(
        "i_{}",
        std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(8)
            .collect::<String>()
    );
    let loop_counter_ident = syn::Ident::new(&loop_counter_name, proc_macro2::Span::call_site());

    let junk_code_block = quote! {
        for #loop_counter_ident in 0..#loop_iterations {
            if #loop_counter_ident > #loop_iterations {
                #(#junk_statements)*
            }
        }
    };

    let original_body = subject_fn.block;
    let new_body_block = syn::parse2(quote! {
        {
            #junk_code_block
            #original_body
        }
    }).expect("Failed to parse new body");

    subject_fn.block = Box::new(new_body_block);

    subject_fn
}
