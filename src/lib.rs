use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hpke::{Deserializable, Kem as KemTrait, OpModeS, PskBundle, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const _KEY_ID: u8 = 1;
const PKR_BYTES: [u8; 32] = [31, 177, 33, 184, 17, 76, 225, 69, 155, 115, 196, 223, 218, 88, 21, 37, 221, 142, 172, 242, 10, 25, 103, 138, 254, 76, 169, 12, 52, 134, 227, 36];

type KemType = hpke::kem::X25519HkdfSha256;
type KdfType = hpke::kdf::HkdfSha256;
type AeadType = hpke::aead::ChaCha20Poly1305;

const HDR: [u8; 7] = [0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x03];
const INFO: [u8; 29] = [109, 101, 115, 115, 97, 103, 101, 47, 98, 104, 116, 116, 112, 32, 114, 101, 113, 117, 101, 115, 116, 0, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x03];

#[wasm_bindgen]
pub fn s( // s for seal
          s: &[u8], // s for seed
          p: &[u8], // p for pt, plaintext
          k: &[u8], // k for psk, pre-shared key
          i: &[u8], // i for psk_id, pre-shared key identifier
) -> Vec<u8> {
    let mut rng = StdRng::from_seed(s.try_into().unwrap());

    // hdr = concat(encode(1, key_id),
    //              encode(2, kem_id),
    //              encode(2, kdf_id),
    //              encode(2, aead_id))
    // let hdr = [
    //     _KEY_ID.to_be_bytes().as_slice(),
    //     KemType::KEM_ID.to_be_bytes().as_slice(),
    //     KdfType::KDF_ID.to_be_bytes().as_slice(),
    //     AeadType::AEAD_ID.to_be_bytes().as_slice(),
    // ].concat();

    // info = concat(encode_str("message/bhttp request"),
    //               encode(1, 0),
    //               HDR)
    // let info = ["message/bhttp request".as_bytes(), &[0u8; 1], &HDR].concat();

    let pkr = <KemType as KemTrait>::PublicKey::from_bytes(&PKR_BYTES).unwrap();

    let mode = if i.len() > 0 {
        OpModeS::Psk(PskBundle { psk: k, psk_id: i })
    } else {
        OpModeS::Base
    };

    // enc, sctxt = SetupBaseS(pkR, info)
    let (enc, mut sender_ctx) = hpke::setup_sender::<AeadType, KdfType, KemType, _>(&mode, &pkr, &INFO, &mut rng).unwrap();

    // ct = sctxt.Seal("", request)
    let mut pt_vec = p.to_vec();
    let tag = sender_ctx.seal_in_place_detached(&mut pt_vec, b"").unwrap();
    let ciphertext = pt_vec;

    // secret = context.Export("message/bhttp response", Nk)
    // todo: AES-128-GCM Nk = 16, AES-256-GCM Nk = 32, ChaCha20Poly1305 Nk = 32
    let mut secret = [0u8; 32];
    sender_ctx.export(b"message/bhttp response", &mut secret).unwrap();

    // enc_request = concat(hdr, enc, ct)
    // result = secret || HDR || enc || ciphertext || tag
    [secret.as_slice(), HDR.as_slice(), enc.to_bytes().as_slice(), ciphertext.as_slice(), tag.to_bytes().as_slice()].concat()
}

#[wasm_bindgen]
pub fn o( // o for open
          s: &[u8], // s for secret
          e: &[u8], // e for enc, encapsulated key
          r: &[u8], // r for enc_response, encapsulated response
) -> Vec<u8> {
    // enc_response = concat(response_nonce, ct)
    // response_nonce = random(max(Nn, Nk))
    // todo: AES-128-GCM = 16, AES-256-GCM = 32, ChaCha20Poly1305 = 32
    let response_nonce = &r[..32];
    let ct = &r[32..];

    // salt = concat(enc, response_nonce)
    let salt = [e, response_nonce].concat();

    // prk = Extract(salt, secret)
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &s);

    // aead_key = Expand(prk, "key", Nk)
    // todo: AES-128-GCM Nk = 16, AES-256-GCM Nk = 32, ChaCha20Poly1305 Nk = 32
    let mut aead_key = [0u8; 32];
    hk.expand(b"key", &mut aead_key).unwrap();

    // aead_nonce = Expand(prk, "nonce", Nn)
    let mut aead_nonce = [0u8; 12];
    hk.expand(b"nonce", &mut aead_nonce).unwrap();

    let mut psk = [0u8; 32];
    hk.expand(b"psk", &mut psk).unwrap();

    // pt = Open(aead_key, aead_nonce, "", ct)
    // todo: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305
    let key = Key::from_slice(&aead_key);
    let nonce = Nonce::from_slice(&aead_nonce);
    let cipher = ChaCha20Poly1305::new(key);
    let mut ct_vec = ct.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut ct_vec).unwrap();
    let pt = ct_vec;

    // result = psk || pt
    [psk.as_slice(), pt.as_slice()].concat()
}
