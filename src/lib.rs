use hpke::{aead::{AeadTag, AesGcm256}, Deserializable, kdf::HkdfSha256, Kem as KemTrait, kem::X25519HkdfSha256, OpModeR, OpModeS, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha256;

#[wasm_bindgen]
pub fn seal(
    seed: &[u8],
    pkr_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let mut rng = StdRng::from_seed(seed.try_into().unwrap());
    let pkr = <Kem as KemTrait>::PublicKey::from_bytes(pkr_bytes).unwrap();
    let mut pt_vec = pt.to_vec();
    let (enc, tag) =
        hpke::single_shot_seal_in_place_detached::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pkr, info, &mut pt_vec, aad, &mut rng).unwrap();
    let ciphertext = pt_vec;
    // result = enc || ciphertext || tag
    [enc.to_bytes().as_slice(), &ciphertext, tag.to_bytes().as_slice()].concat()
}

#[wasm_bindgen]
pub fn open(
    enc_bytes: &[u8],
    skr_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // ct = ciphertext || tag
    // AesGcm256 Nt = 16
    let idx = ct.len() - 16;
    let ciphertext = &ct[..idx];
    let tag_bytes = &ct[idx..];

    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes).unwrap();
    let skr = <Kem as KemTrait>::PrivateKey::from_bytes(skr_bytes).unwrap();
    let tag = AeadTag::<Aead>::from_bytes(tag_bytes).unwrap();

    let mut ciphertext_vec = ciphertext.to_vec();
    hpke::single_shot_open_in_place_detached::<Aead, Kdf, Kem>(&OpModeR::Base, &skr, &enc, info, &mut ciphertext_vec, aad, &tag).unwrap();

    let pt = ciphertext_vec;
    pt
}
