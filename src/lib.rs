use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hpke::{aead::{Aead, AesGcm128}, Deserializable, kdf::{HkdfSha256, Kdf}, Kem as KemTrait, kem::X25519HkdfSha256, OpModeS, PskBundle, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

type KemType = X25519HkdfSha256;
type AeadType = AesGcm128;
type KdfType = HkdfSha256;

const KEY_ID: u8 = 1;
const PKR_BYTES: [u8; 32] = [31, 177, 33, 184, 17, 76, 225, 69, 155, 115, 196, 223, 218, 88, 21, 37, 221, 142, 172, 242, 10, 25, 103, 138, 254, 76, 169, 12, 52, 134, 227, 36];

#[wasm_bindgen]
pub fn seal(
    seed: &[u8],
    pt: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Vec<u8> {
    let mut rng = StdRng::from_seed(seed.try_into().unwrap());

    // hdr = concat(encode(1, key_id),
    //              encode(2, kem_id),
    //              encode(2, kdf_id),
    //              encode(2, aead_id))
    let hdr = [
        KEY_ID.to_be_bytes().as_slice(),
        KemType::KEM_ID.to_be_bytes().as_slice(),
        KdfType::KDF_ID.to_be_bytes().as_slice(),
        AeadType::AEAD_ID.to_be_bytes().as_slice(),
    ].concat();

    // info = concat(encode_str("message/bhttp request"),
    //               encode(1, 0),
    //               hdr)
    let info = ["message/bhttp request".as_bytes(), &[0u8; 1], &hdr].concat();

    let pkr = <KemType as KemTrait>::PublicKey::from_bytes(&PKR_BYTES).unwrap();

    let mode = if psk_id.len() > 0 {
        OpModeS::Psk(PskBundle { psk, psk_id })
    } else {
        OpModeS::Base
    };

    // enc, sctxt = SetupBaseS(pkR, info)
    let (enc, mut sender_ctx) = hpke::setup_sender::<AeadType, KdfType, KemType, _>(&mode, &pkr, &info, &mut rng).unwrap();

    // ct = sctxt.Seal("", request)
    let mut pt_vec = pt.to_vec();
    let tag = sender_ctx.seal_in_place_detached(&mut pt_vec, b"").unwrap();
    let ciphertext = pt_vec;

    // secret = context.Export("message/bhttp response", Nk)
    // todo: AES-128-GCM Nk = 16, AES-256-GCM Nk = 32, ChaCha20Poly1305 Nk = 32
    let mut secret = [0u8; 16];
    sender_ctx.export(b"message/bhttp response", &mut secret).unwrap();

    // enc_request = concat(hdr, enc, ct)
    // result = secret || hdr || enc || ciphertext || tag
    [&secret, hdr.as_slice(), enc.to_bytes().as_slice(), &ciphertext, tag.to_bytes().as_slice()].concat()
}

#[wasm_bindgen]
pub fn open(
    secret: &[u8],
    enc: &[u8],
    res: &[u8],
) -> Vec<u8> {
    // enc_response = concat(response_nonce, ct)
    // response_nonce = random(max(Nn, Nk))
    // todo: AES-128-GCM = 16, AES-256-GCM = 32, ChaCha20Poly1305 = 32
    let response_nonce = &res[..16];
    let ct = &res[16..];

    // salt = concat(enc, response_nonce)
    let salt = [enc, response_nonce].concat();

    // prk = Extract(salt, secret)
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &secret);

    // aead_key = Expand(prk, "key", Nk)
    // todo: AES-128-GCM Nk = 16, AES-256-GCM Nk = 32, ChaCha20Poly1305 Nk = 32
    let mut aead_key = [0u8; 16];
    hk.expand(b"key", &mut aead_key).unwrap();

    // aead_nonce = Expand(prk, "nonce", Nn)
    let mut aead_nonce = [0u8; 12];
    hk.expand(b"nonce", &mut aead_nonce).unwrap();

    // pt = Open(aead_key, aead_nonce, "", ct)
    // todo: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305
    let cipher = Aes128Gcm::new_from_slice(&aead_key).unwrap();
    let nonce = Nonce::from_slice(&aead_nonce);
    let mut ct_vec = ct.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut ct_vec).unwrap();
    let pt = ct_vec;
    pt
}
