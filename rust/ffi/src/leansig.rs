use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use leansig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// Type alias for the concrete signature scheme instance
type SigScheme = SIGTopLevelTargetSumLifetime18Dim64Base8;
type LeanSigPrivateKey = <SigScheme as SignatureScheme>::SecretKey;
type LeanSigPublicKey = <SigScheme as SignatureScheme>::PublicKey;
type LeanSigSignature = <SigScheme as SignatureScheme>::Signature;

#[repr(C)]
pub struct PrivateKey {
    inner: LeanSigPrivateKey,
}

#[repr(C)]
pub struct PublicKey {
    pub inner: LeanSigPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: LeanSigSignature,
}

#[repr(C)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl PrivateKey {
    pub fn new(inner: LeanSigPrivateKey) -> Self {
        Self { inner }
    }

    pub fn generate<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (PublicKey, Self) {
        let (public_key, private_key) = SigScheme::key_gen(rng, activation_epoch, num_active_epochs);
        (PublicKey::new(public_key), Self::new(private_key))
    }

    pub fn sign(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32) -> Result<Signature, String> {
        Ok(Signature::new(
            <SigScheme as SignatureScheme>::sign(&self.inner, epoch, message)
                .map_err(|e| format!("{:?}", e))?,
        ))
    }
}

impl PublicKey {
    pub fn new(inner: LeanSigPublicKey) -> Self {
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: LeanSigSignature) -> Self {
        Self { inner }
    }

    pub fn verify(&self, message: &[u8; MESSAGE_LENGTH], public_key: &PublicKey, epoch: u32) -> bool {
        <SigScheme as SignatureScheme>::verify(&public_key.inner, epoch, message, &self.inner)
    }
}

// FFI Functions

/// Returns the lifetime of the signature scheme
#[no_mangle]
pub extern "C" fn leansig_lifetime() -> u64 {
    SigScheme::LIFETIME
}

/// Returns the message length constant
#[no_mangle]
pub extern "C" fn leansig_message_length() -> usize {
    MESSAGE_LENGTH
}

/// Generate a new key pair from a seed phrase
/// # Safety
/// seed_phrase must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed_phrase: *const c_char,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut KeyPair {
    let seed_phrase = unsafe {
        if seed_phrase.is_null() {
            return ptr::null_mut();
        }
        CStr::from_ptr(seed_phrase).to_string_lossy().into_owned()
    };

    let mut hasher = Sha256::new();
    hasher.update(seed_phrase.as_bytes());
    let seed = hasher.finalize().into();

    let mut rng = <StdRng as SeedableRng>::from_seed(seed);
    let (public_key, private_key) = PrivateKey::generate(
        &mut rng,
        activation_epoch,
        num_active_epochs,
    );

    let keypair = Box::new(KeyPair {
        public_key,
        private_key,
    });

    Box::into_raw(keypair)
}

/// Free a key pair
/// # Safety
/// keypair must be null or a valid pointer returned from leansig_keypair_generate
#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_free(keypair: *mut KeyPair) {
    if !keypair.is_null() {
        unsafe {
            let _ = Box::from_raw(keypair);
        }
    }
}

/// Get public key pointer from keypair
/// # Safety
/// keypair must be null or a valid KeyPair pointer
#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_get_public_key(
    keypair: *const KeyPair,
) -> *const PublicKey {
    if keypair.is_null() {
        return ptr::null();
    }
    &(*keypair).public_key
}

/// Get private key pointer from keypair
/// # Safety
/// keypair must be null or a valid KeyPair pointer
#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_get_private_key(
    keypair: *const KeyPair,
) -> *const PrivateKey {
    if keypair.is_null() {
        return ptr::null();
    }
    &(*keypair).private_key
}

/// Sign a message
/// # Safety
/// private_key must be valid, message_ptr must point to MESSAGE_LENGTH bytes
#[no_mangle]
pub unsafe extern "C" fn leansig_sign(
    private_key: *const PrivateKey,
    message_ptr: *const u8,
    epoch: u32,
) -> *mut Signature {
    if private_key.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let private_key_ref = &*private_key;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => return ptr::null_mut(),
        };

        let signature = match private_key_ref.sign(message_array, epoch) {
            Ok(sig) => sig,
            Err(_) => return ptr::null_mut(),
        };

        Box::into_raw(Box::new(signature))
    }
}

/// Free a signature
/// # Safety
/// signature must be null or a valid Signature pointer
#[no_mangle]
pub unsafe extern "C" fn leansig_signature_free(signature: *mut Signature) {
    if !signature.is_null() {
        unsafe {
            let _ = Box::from_raw(signature);
        }
    }
}

/// Verify a signature
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn leansig_verify(
    public_key: *const PublicKey,
    message_ptr: *const u8,
    epoch: u32,
    signature: *const Signature,
) -> i32 {
    if public_key.is_null() || message_ptr.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let public_key_ref = &*public_key;
        let signature_ref = &*signature;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => return -1,
        };

        match signature_ref.verify(message_array, public_key_ref, epoch) {
            true => 1,
            false => 0,
        }
    }
}
