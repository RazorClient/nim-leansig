use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::Once;

use p3_koala_bear::KoalaBear;
use rec_aggregation::xmss_aggregate::{
    xmss_aggregate_signatures, xmss_setup_aggregation_program, xmss_verify_aggregated_signatures,
    XmssAggregateError,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use whir_p3::precompute_dft_twiddles;
use xmss::{XmssSignatureError, XmssVerifyError};

const XMSS_MESSAGE_LEN: usize = 32;

// FFI-visible wrappers
#[repr(C)]
pub struct XmssSecretKey {
    pub(crate) inner: xmss::XmssSecretKey,
}

#[repr(C)]
pub struct XmssPublicKey {
    pub(crate) inner: xmss::XmssPublicKey,
}

#[repr(C)]
pub struct XmssSignature {
    pub(crate) inner: xmss::XmssSignature,
}

#[repr(C)]
pub struct XmssKeyPair {
    pub public_key: XmssPublicKey,
    pub secret_key: XmssSecretKey,
}

#[repr(C)]
pub struct XmssAggregateProof {
    pub bytes: Vec<u8>,
}

impl XmssSecretKey {
    fn new(inner: xmss::XmssSecretKey) -> Self {
        Self { inner }
    }
}

impl XmssPublicKey {
    fn new(inner: xmss::XmssPublicKey) -> Self {
        Self { inner }
    }
}

impl XmssSignature {
    fn new(inner: xmss::XmssSignature) -> Self {
        Self { inner }
    }
}

impl XmssAggregateProof {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

fn bytes_to_digest(bytes: &[u8]) -> Option<[KoalaBear; 8]> {
    if bytes.len() != XMSS_MESSAGE_LEN {
        return None;
    }
    let mut out = [KoalaBear::new(0); 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        out[i] = KoalaBear::new(word);
    }
    Some(out)
}

fn seed_from_phrase(seed_phrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed_phrase.as_bytes());
    hasher.finalize().into()
}

fn randomness_from_message(message: &[u8], slot: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(message);
    hasher.update(slot.to_le_bytes());
    hasher.finalize().into()
}

fn copy_wots_signature(sig: &xmss::WotsSignature) -> xmss::WotsSignature {
    xmss::WotsSignature {
        chain_tips: sig.chain_tips,
        randomness: sig.randomness,
    }
}

fn copy_xmss_signature(sig: &xmss::XmssSignature) -> xmss::XmssSignature {
    xmss::XmssSignature {
        wots_signature: copy_wots_signature(&sig.wots_signature),
        slot: sig.slot,
        merkle_proof: sig.merkle_proof.clone(),
    }
}

fn copy_public_key(pk: &xmss::XmssPublicKey) -> xmss::XmssPublicKey {
    xmss::XmssPublicKey {
        merkle_root: pk.merkle_root,
        first_slot: pk.first_slot,
        log_lifetime: pk.log_lifetime,
    }
}

static XMSS_PROVER_INIT: Once = Once::new();
static XMSS_VERIFIER_INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn xmss_setup_prover() {
    XMSS_PROVER_INIT.call_once(|| {
        xmss_setup_aggregation_program();
        precompute_dft_twiddles::<KoalaBear>(1 << 24);
    });
}

#[no_mangle]
pub extern "C" fn xmss_setup_verifier() {
    XMSS_VERIFIER_INIT.call_once(xmss_setup_aggregation_program);
}

#[no_mangle]
pub extern "C" fn xmss_message_length() -> usize {
    XMSS_MESSAGE_LEN
}

#[no_mangle]
pub unsafe extern "C" fn xmss_keypair_generate(
    seed_phrase: *const c_char,
    first_slot: u64,
    log_lifetime: usize,
) -> *mut XmssKeyPair {
    if seed_phrase.is_null() {
        return ptr::null_mut();
    }
    let seed_phrase = match unsafe { CStr::from_ptr(seed_phrase).to_str() } {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let seed = seed_from_phrase(seed_phrase);
    let (sk, pk) = match xmss::xmss_key_gen(seed, first_slot, log_lifetime) {
        Ok(res) => res,
        Err(_) => return ptr::null_mut(),
    };

    let kp = XmssKeyPair {
        public_key: XmssPublicKey::new(pk),
        secret_key: XmssSecretKey::new(sk),
    };
    Box::into_raw(Box::new(kp))
}

#[no_mangle]
pub unsafe extern "C" fn xmss_keypair_free(kp: *mut XmssKeyPair) {
    if !kp.is_null() {
        drop(Box::from_raw(kp));
    }
}

#[no_mangle]
pub unsafe extern "C" fn xmss_keypair_get_public_key(kp: *const XmssKeyPair) -> *const XmssPublicKey {
    if kp.is_null() {
        return ptr::null();
    }
    &(*kp).public_key
}

#[no_mangle]
pub unsafe extern "C" fn xmss_keypair_get_secret_key(kp: *const XmssKeyPair) -> *const XmssSecretKey {
    if kp.is_null() {
        return ptr::null();
    }
    &(*kp).secret_key
}

#[no_mangle]
pub unsafe extern "C" fn xmss_sign(
    secret_key: *const XmssSecretKey,
    message_ptr: *const u8,
    slot: u64,
) -> *mut XmssSignature {
    if secret_key.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }

    let message = slice::from_raw_parts(message_ptr, XMSS_MESSAGE_LEN);
    let digest = match bytes_to_digest(message) {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let rand_seed = randomness_from_message(message, slot);
    let sk = &(*secret_key).inner;
    let sig = match xmss::xmss_sign(rand_seed, sk, &digest, slot) {
        Ok(s) => s,
        Err(XmssSignatureError::SlotTooEarly | XmssSignatureError::SlotTooLate) => return ptr::null_mut(),
    };

    Box::into_raw(Box::new(XmssSignature::new(sig)))
}

#[no_mangle]
pub unsafe extern "C" fn xmss_signature_free(sig: *mut XmssSignature) {
    if !sig.is_null() {
        drop(Box::from_raw(sig));
    }
}

#[no_mangle]
pub unsafe extern "C" fn xmss_verify(
    public_key: *const XmssPublicKey,
    message_ptr: *const u8,
    slot: u64,
    signature: *const XmssSignature,
) -> bool {
    if public_key.is_null() || message_ptr.is_null() || signature.is_null() {
        return false;
    }

    let message = slice::from_raw_parts(message_ptr, XMSS_MESSAGE_LEN);
    let digest = match bytes_to_digest(message) {
        Some(d) => d,
        None => return false,
    };

    match xmss::xmss_verify(
        &(*public_key).inner,
        &digest,
        &(*signature).inner,
        slot,
    ) {
        Ok(_) => true,
        Err(
            XmssVerifyError::SlotTooEarly
            | XmssVerifyError::SlotTooLate
            | XmssVerifyError::InvalidMerklePath
            | XmssVerifyError::InvalidWots,
        ) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate(
    public_keys: *const *const XmssPublicKey,
    num_keys: usize,
    signatures: *const *const XmssSignature,
    num_sigs: usize,
    message_ptr: *const u8,
    slot: u64,
) -> *mut XmssAggregateProof {
    xmss_setup_prover();

    if public_keys.is_null() || signatures.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }
    if num_keys == 0 || num_keys != num_sigs {
        return ptr::null_mut();
    }

    let digest_bytes = slice::from_raw_parts(message_ptr, XMSS_MESSAGE_LEN);
    let digest = match bytes_to_digest(digest_bytes) {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let pk_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    for &pk_ptr in pk_ptrs {
        if pk_ptr.is_null() {
            return ptr::null_mut();
        }
        pks.push(copy_public_key(&(*pk_ptr).inner));
    }

    let sig_ptrs = slice::from_raw_parts(signatures, num_sigs);
    let mut sigs = Vec::with_capacity(num_sigs);
    for &sig_ptr in sig_ptrs {
        if sig_ptr.is_null() {
            return ptr::null_mut();
        }
        sigs.push(copy_xmss_signature(&(*sig_ptr).inner));
    }

    let proof_bytes = match xmss_aggregate_signatures(&pks, &sigs, digest, slot) {
        Ok(bytes) => bytes,
        Err(XmssAggregateError::WrongSignatureCount | XmssAggregateError::InvalidSigature) => {
            return ptr::null_mut()
        }
    };

    Box::into_raw(Box::new(XmssAggregateProof::new(proof_bytes)))
}

#[no_mangle]
pub unsafe extern "C" fn xmss_verify_aggregated(
    public_keys: *const *const XmssPublicKey,
    num_keys: usize,
    message_ptr: *const u8,
    proof: *const XmssAggregateProof,
    slot: u64,
) -> bool {
    xmss_setup_verifier();

    if public_keys.is_null() || message_ptr.is_null() || proof.is_null() {
        return false;
    }

    let digest_bytes = slice::from_raw_parts(message_ptr, XMSS_MESSAGE_LEN);
    let digest = match bytes_to_digest(digest_bytes) {
        Some(d) => d,
        None => return false,
    };

    let pk_ptrs = slice::from_raw_parts(public_keys, num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    for &pk_ptr in pk_ptrs {
        if pk_ptr.is_null() {
            return false;
        }
        pks.push(copy_public_key(&(*pk_ptr).inner));
    }

    xmss_verify_aggregated_signatures(&pks, digest, &(*proof).bytes, slot).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_proof_len(proof: *const XmssAggregateProof) -> usize {
    if proof.is_null() {
        0
    } else {
        (*proof).bytes.len()
    }
}

#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_proof_copy_bytes(
    proof: *const XmssAggregateProof,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if proof.is_null() || buffer.is_null() {
        return 0;
    }
    let data = &(*proof).bytes;
    if buffer_len < data.len() {
        return 0;
    }
    let out = slice::from_raw_parts_mut(buffer, buffer_len);
    out[..data.len()].copy_from_slice(data);
    data.len()
}

#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_proof_from_bytes(
    bytes: *const u8,
    len: usize,
) -> *mut XmssAggregateProof {
    if bytes.is_null() || len == 0 {
        return ptr::null_mut();
    }
    let slice = slice::from_raw_parts(bytes, len);
    Box::into_raw(Box::new(XmssAggregateProof::new(slice.to_vec())))
}

#[no_mangle]
pub unsafe extern "C" fn xmss_aggregate_proof_free(proof: *mut XmssAggregateProof) {
    if !proof.is_null() {
        drop(Box::from_raw(proof));
    }
}
