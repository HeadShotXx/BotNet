use quote::quote;
use proc_macro2::TokenStream;

#[derive(Debug, Clone, Copy)]
pub enum Codec {
    Base36,
    Base45,
    Base58,
    Base85,
    Base91,
    Base122,
}

impl Codec {
    pub fn all() -> Vec<Self> {
        vec![
            Codec::Base36,
            Codec::Base45,
            Codec::Base58,
            Codec::Base85,
            Codec::Base91,
            Codec::Base122,
        ]
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Codec::Base36 => base36::encode(data).as_bytes().to_vec(),
            Codec::Base45 => base45::encode(data).as_bytes().to_vec(),
            Codec::Base58 => bs58::encode(data).into_string().into_bytes(),
            Codec::Base85 => base85::encode(data).as_bytes().to_vec(),
            Codec::Base91 => base91::slice_encode(data),
            Codec::Base122 => base122_rs::encode(data).as_bytes().to_vec(),
        }
    }

    pub fn get_decode_logic(&self, data_var: &syn::Ident) -> TokenStream {
        match self {
            Codec::Base36 => quote! { let #data_var = base36::decode(&String::from_utf8_lossy(&#data_var).to_lowercase()).unwrap(); },
            Codec::Base45 => quote! { let #data_var = base45::decode(String::from_utf8_lossy(&#data_var).as_ref()).unwrap(); },
            Codec::Base58 => quote! { let #data_var = bs58::decode(String::from_utf8_lossy(&#data_var).as_ref()).into_vec().unwrap(); },
            Codec::Base85 => quote! { let #data_var = base85::decode(&String::from_utf8_lossy(&#data_var).replace("{", "_").replace("}", "_")).unwrap(); },
            Codec::Base91 => quote! { let #data_var = base91::slice_decode(&#data_var); },
            Codec::Base122 => quote! { let #data_var = base122_rs::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
        }
    }
}