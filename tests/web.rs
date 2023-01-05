//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use hpke::{
    Kem as KemTrait, kem::X25519HkdfSha256, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};
use wasm_bindgen_test::*;

use hpke_wasm::{open, seal};

type Kem = X25519HkdfSha256;

const INFO: &[u8] = b"example session";

wasm_bindgen_test_configure!(run_in_browser);

fn gen_keypair() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut rng = StdRng::from_entropy();
    Kem::gen_keypair(&mut rng)
}

#[wasm_bindgen_test]
fn hpke_test() {
    // Generate server keypair
    let (ssk, spk) = gen_keypair();
    // Serialize server keypair
    let ssk_bytes = ssk.to_bytes();
    let spk_bytes = spk.to_bytes();

    // plaintext
    let pt = b"Kat Branchman";
    // aad
    let aad = b"Mr. Meow";

    // Client encrypt plaintext
    let result = seal(&[7u8; 32], spk_bytes.as_slice(), INFO, aad, pt, &[1; 1], &[1; 1]);

    // result = enc || ct
    // X25519HkdfSha256 Nenc = 32
    let enc_bytes = &result[..32];
    let ct = &result[32..];

    // send result to remote

    // Client decrypt ciphertext
    let decrypted_pt = open(&enc_bytes, ssk_bytes.as_slice(), INFO, aad, &ct, &[1; 1], &[1; 1]);

    // Make sure everything decrypted correctly
    assert_eq!(decrypted_pt, pt);
}