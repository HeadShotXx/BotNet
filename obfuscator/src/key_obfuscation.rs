use proc_macro2::TokenStream;
use quote::quote;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

#[derive(Debug, Clone, Copy)]
pub enum KeyCodec {
    Hex,
    Rot,
}

impl KeyCodec {
    fn all() -> Vec<Self> {
        vec![KeyCodec::Hex, KeyCodec::Rot]
    }

    pub fn encode(self, nibble: u8, rot: u8) -> String {
        match self {
            KeyCodec::Hex => format!("{:x}", nibble),
            KeyCodec::Rot => format!("{:x}", (nibble.wrapping_add(rot)) & 0x0F),
        }
    }

    pub fn get_decode_logic(self, s: &str, rot: u8) -> TokenStream {
        match self {
            KeyCodec::Hex => {
                quote! { u8::from_str_radix(#s, 16).unwrap() }
            }
            KeyCodec::Rot => {
                quote! { (u8::from_str_radix(#s, 16).unwrap().wrapping_sub(#rot)) & 0x0F }
            }
        }
    }
}

pub struct ObfuscatedKey {
    pub encoded_high: String,
    pub encoded_low: String,
    pub high_codec: KeyCodec,
    pub low_codec: KeyCodec,
    pub high_rot: u8,
    pub low_rot: u8,
}

pub fn obfuscate(key: u8) -> ObfuscatedKey {
    let mut rng = thread_rng();
    let mut codecs = KeyCodec::all();
    codecs.shuffle(&mut rng);

    let high_nibble = key >> 4;
    let low_nibble = key & 0x0F;

    let high_codec = codecs[0];
    let low_codec = codecs[1];

    let high_rot = rng.gen_range(1..16);
    let low_rot = rng.gen_range(1..16);

    let encoded_high = high_codec.encode(high_nibble, high_rot);
    let encoded_low = low_codec.encode(low_nibble, low_rot);

    ObfuscatedKey {
        encoded_high,
        encoded_low,
        high_codec,
        low_codec,
        high_rot,
        low_rot,
    }
}