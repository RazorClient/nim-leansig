use leansig::inc_encoding::target_sum::TargetSumEncoding;
use leansig::serialization::Serializable;
use leansig::signature::generalized_xmss::GeneralizedXMSSSignatureScheme;
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::{
    SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W1Off10, SIGTargetSumLifetime18W2NoOff,
    SIGTargetSumLifetime18W2Off10, SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W4Off10,
    SIGTargetSumLifetime18W8NoOff, SIGTargetSumLifetime18W8Off10,
};
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::{
    SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W1Off10, SIGTargetSumLifetime20W2NoOff,
    SIGTargetSumLifetime20W2Off10, SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W4Off10,
    SIGTargetSumLifetime20W8NoOff, SIGTargetSumLifetime20W8Off10,
};
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use leansig::symmetric::message_hash::MessageHash;
use leansig::symmetric::message_hash::poseidon::PoseidonMessageHash;
use leansig::symmetric::prf::shake_to_field::ShakePRFtoF;
use leansig::symmetric::tweak_hash::poseidon::PoseidonTweakHash;
use leansig::MESSAGE_LENGTH;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};

type SchemeDefault = SIGTopLevelTargetSumLifetime18Dim64Base8;
type SchemePoseidon18W1NoOff = SIGTargetSumLifetime18W1NoOff;
type SchemePoseidon18W1Off10 = SIGTargetSumLifetime18W1Off10;
type SchemePoseidon18W2NoOff = SIGTargetSumLifetime18W2NoOff;
type SchemePoseidon18W2Off10 = SIGTargetSumLifetime18W2Off10;
type SchemePoseidon18W4NoOff = SIGTargetSumLifetime18W4NoOff;
type SchemePoseidon18W4Off10 = SIGTargetSumLifetime18W4Off10;
type SchemePoseidon18W8NoOff = SIGTargetSumLifetime18W8NoOff;
type SchemePoseidon18W8Off10 = SIGTargetSumLifetime18W8Off10;
type SchemePoseidon20W1NoOff = SIGTargetSumLifetime20W1NoOff;
type SchemePoseidon20W1Off10 = SIGTargetSumLifetime20W1Off10;
type SchemePoseidon20W2NoOff = SIGTargetSumLifetime20W2NoOff;
type SchemePoseidon20W2Off10 = SIGTargetSumLifetime20W2Off10;
type SchemePoseidon20W4NoOff = SIGTargetSumLifetime20W4NoOff;
type SchemePoseidon20W4Off10 = SIGTargetSumLifetime20W4Off10;
type SchemePoseidon20W8NoOff = SIGTargetSumLifetime20W8NoOff;
type SchemePoseidon20W8Off10 = SIGTargetSumLifetime20W8Off10;
type SchemeTopLevel8 = SIGTopLevelTargetSumLifetime8Dim64Base8;
type SchemeCoreLargeBase = GeneralizedXMSSSignatureScheme<
    ShakePRFtoF<4, 8>,
    TargetSumEncoding<PoseidonMessageHash<4, 8, 8, 32, 256, 2, 9>, { 1 << 12 }>,
    PoseidonTweakHash<4, 4, 2, 8, 32>,
    10,
>;
type SchemeCoreLargeDimension = GeneralizedXMSSSignatureScheme<
    ShakePRFtoF<8, 8>,
    TargetSumEncoding<PoseidonMessageHash<4, 8, 8, 256, 2, 2, 9>, 128>,
    PoseidonTweakHash<4, 8, 2, 8, 256>,
    10,
>;
type CoreTargetMh = PoseidonMessageHash<5, 5, 5, 163, 2, 2, 9>;
const CORE_TARGET_EXPECTED_SUM: usize = CoreTargetMh::DIMENSION * (CoreTargetMh::BASE - 1) / 2;
type SchemeCoreTargetSum = GeneralizedXMSSSignatureScheme<
    ShakePRFtoF<7, 5>,
    TargetSumEncoding<CoreTargetMh, CORE_TARGET_EXPECTED_SUM>,
    PoseidonTweakHash<5, 7, 2, 9, 163>,
    6,
>;

// Keep this order stable: scheme IDs are part of the C ABI.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeanSigSchemeId {
    TopLevelTargetSumLifetime18Dim64Base8 = 0,
    Poseidon18W1NoOff,
    Poseidon18W1Off10,
    Poseidon18W2NoOff,
    Poseidon18W2Off10,
    Poseidon18W4NoOff,
    Poseidon18W4Off10,
    Poseidon18W8NoOff,
    Poseidon18W8Off10,
    Poseidon20W1NoOff,
    Poseidon20W1Off10,
    Poseidon20W2NoOff,
    Poseidon20W2Off10,
    Poseidon20W4NoOff,
    Poseidon20W4Off10,
    Poseidon20W8NoOff,
    Poseidon20W8Off10,
    TopLevelTargetSumLifetime8Dim64Base8,
    CoreLargeBasePoseidon,
    CoreLargeDimensionPoseidon,
    CoreTargetSumPoseidon,
}

const FIRST_SCHEME_ID: u32 = LeanSigSchemeId::TopLevelTargetSumLifetime18Dim64Base8 as u32;
const LAST_SCHEME_ID: u32 = LeanSigSchemeId::CoreTargetSumPoseidon as u32;

impl LeanSigSchemeId {
    fn from_raw(raw: u32) -> Option<Self> {
        if !(FIRST_SCHEME_ID..=LAST_SCHEME_ID).contains(&raw) {
            return None;
        }
        Some(unsafe { std::mem::transmute::<u32, Self>(raw) })
    }
}

const DEFAULT_SCHEME_ID: LeanSigSchemeId = LeanSigSchemeId::TopLevelTargetSumLifetime18Dim64Base8;

enum AnySecretKey {
    SchemeDefault(<SchemeDefault as SignatureScheme>::SecretKey),
    SchemePoseidon18W1NoOff(<SchemePoseidon18W1NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon18W1Off10(<SchemePoseidon18W1Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon18W2NoOff(<SchemePoseidon18W2NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon18W2Off10(<SchemePoseidon18W2Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon18W4NoOff(<SchemePoseidon18W4NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon18W4Off10(<SchemePoseidon18W4Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon18W8NoOff(<SchemePoseidon18W8NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon18W8Off10(<SchemePoseidon18W8Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon20W1NoOff(<SchemePoseidon20W1NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon20W1Off10(<SchemePoseidon20W1Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon20W2NoOff(<SchemePoseidon20W2NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon20W2Off10(<SchemePoseidon20W2Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon20W4NoOff(<SchemePoseidon20W4NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon20W4Off10(<SchemePoseidon20W4Off10 as SignatureScheme>::SecretKey),
    SchemePoseidon20W8NoOff(<SchemePoseidon20W8NoOff as SignatureScheme>::SecretKey),
    SchemePoseidon20W8Off10(<SchemePoseidon20W8Off10 as SignatureScheme>::SecretKey),
    SchemeTopLevel8(<SchemeTopLevel8 as SignatureScheme>::SecretKey),
    SchemeCoreLargeBase(<SchemeCoreLargeBase as SignatureScheme>::SecretKey),
    SchemeCoreLargeDimension(<SchemeCoreLargeDimension as SignatureScheme>::SecretKey),
    SchemeCoreTargetSum(<SchemeCoreTargetSum as SignatureScheme>::SecretKey),
}

enum AnyPublicKey {
    SchemeDefault(<SchemeDefault as SignatureScheme>::PublicKey),
    SchemePoseidon18W1NoOff(<SchemePoseidon18W1NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon18W1Off10(<SchemePoseidon18W1Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon18W2NoOff(<SchemePoseidon18W2NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon18W2Off10(<SchemePoseidon18W2Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon18W4NoOff(<SchemePoseidon18W4NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon18W4Off10(<SchemePoseidon18W4Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon18W8NoOff(<SchemePoseidon18W8NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon18W8Off10(<SchemePoseidon18W8Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon20W1NoOff(<SchemePoseidon20W1NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon20W1Off10(<SchemePoseidon20W1Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon20W2NoOff(<SchemePoseidon20W2NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon20W2Off10(<SchemePoseidon20W2Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon20W4NoOff(<SchemePoseidon20W4NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon20W4Off10(<SchemePoseidon20W4Off10 as SignatureScheme>::PublicKey),
    SchemePoseidon20W8NoOff(<SchemePoseidon20W8NoOff as SignatureScheme>::PublicKey),
    SchemePoseidon20W8Off10(<SchemePoseidon20W8Off10 as SignatureScheme>::PublicKey),
    SchemeTopLevel8(<SchemeTopLevel8 as SignatureScheme>::PublicKey),
    SchemeCoreLargeBase(<SchemeCoreLargeBase as SignatureScheme>::PublicKey),
    SchemeCoreLargeDimension(<SchemeCoreLargeDimension as SignatureScheme>::PublicKey),
    SchemeCoreTargetSum(<SchemeCoreTargetSum as SignatureScheme>::PublicKey),
}

enum AnySignature {
    SchemeDefault(<SchemeDefault as SignatureScheme>::Signature),
    SchemePoseidon18W1NoOff(<SchemePoseidon18W1NoOff as SignatureScheme>::Signature),
    SchemePoseidon18W1Off10(<SchemePoseidon18W1Off10 as SignatureScheme>::Signature),
    SchemePoseidon18W2NoOff(<SchemePoseidon18W2NoOff as SignatureScheme>::Signature),
    SchemePoseidon18W2Off10(<SchemePoseidon18W2Off10 as SignatureScheme>::Signature),
    SchemePoseidon18W4NoOff(<SchemePoseidon18W4NoOff as SignatureScheme>::Signature),
    SchemePoseidon18W4Off10(<SchemePoseidon18W4Off10 as SignatureScheme>::Signature),
    SchemePoseidon18W8NoOff(<SchemePoseidon18W8NoOff as SignatureScheme>::Signature),
    SchemePoseidon18W8Off10(<SchemePoseidon18W8Off10 as SignatureScheme>::Signature),
    SchemePoseidon20W1NoOff(<SchemePoseidon20W1NoOff as SignatureScheme>::Signature),
    SchemePoseidon20W1Off10(<SchemePoseidon20W1Off10 as SignatureScheme>::Signature),
    SchemePoseidon20W2NoOff(<SchemePoseidon20W2NoOff as SignatureScheme>::Signature),
    SchemePoseidon20W2Off10(<SchemePoseidon20W2Off10 as SignatureScheme>::Signature),
    SchemePoseidon20W4NoOff(<SchemePoseidon20W4NoOff as SignatureScheme>::Signature),
    SchemePoseidon20W4Off10(<SchemePoseidon20W4Off10 as SignatureScheme>::Signature),
    SchemePoseidon20W8NoOff(<SchemePoseidon20W8NoOff as SignatureScheme>::Signature),
    SchemePoseidon20W8Off10(<SchemePoseidon20W8Off10 as SignatureScheme>::Signature),
    SchemeTopLevel8(<SchemeTopLevel8 as SignatureScheme>::Signature),
    SchemeCoreLargeBase(<SchemeCoreLargeBase as SignatureScheme>::Signature),
    SchemeCoreLargeDimension(<SchemeCoreLargeDimension as SignatureScheme>::Signature),
    SchemeCoreTargetSum(<SchemeCoreTargetSum as SignatureScheme>::Signature),
}

#[repr(C)]
pub struct PrivateKey {
    scheme: LeanSigSchemeId,
    inner: AnySecretKey,
}

#[repr(C)]
pub struct PublicKey {
    scheme: LeanSigSchemeId,
    inner: AnyPublicKey,
}

#[repr(C)]
pub struct Signature {
    scheme: LeanSigSchemeId,
    inner: AnySignature,
}

#[repr(C)]
pub struct KeyPair {
    scheme: LeanSigSchemeId,
    public_key: PublicKey,
    private_key: PrivateKey,
}

static LEANSIG_LAST_ERROR: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

fn error_storage() -> &'static Mutex<Vec<u8>> {
    LEANSIG_LAST_ERROR.get_or_init(|| Mutex::new(vec![0]))
}

fn set_last_error(message: impl AsRef<str>) {
    let mut bytes = message.as_ref().as_bytes().to_vec();
    bytes.retain(|b| *b != 0);
    bytes.push(0);
    if let Ok(mut guard) = error_storage().lock() {
        *guard = bytes;
    }
}

fn clear_last_error() {
    set_last_error("");
}

fn parse_scheme_id(scheme_id: u32) -> Result<LeanSigSchemeId, String> {
    LeanSigSchemeId::from_raw(scheme_id).ok_or_else(|| format!("unknown scheme id {scheme_id}"))
}

fn scheme_lifetime(scheme: LeanSigSchemeId) -> u64 {
    match scheme {
        LeanSigSchemeId::TopLevelTargetSumLifetime18Dim64Base8 => SchemeDefault::LIFETIME,
        LeanSigSchemeId::Poseidon18W1NoOff => SchemePoseidon18W1NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon18W1Off10 => SchemePoseidon18W1Off10::LIFETIME,
        LeanSigSchemeId::Poseidon18W2NoOff => SchemePoseidon18W2NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon18W2Off10 => SchemePoseidon18W2Off10::LIFETIME,
        LeanSigSchemeId::Poseidon18W4NoOff => SchemePoseidon18W4NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon18W4Off10 => SchemePoseidon18W4Off10::LIFETIME,
        LeanSigSchemeId::Poseidon18W8NoOff => SchemePoseidon18W8NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon18W8Off10 => SchemePoseidon18W8Off10::LIFETIME,
        LeanSigSchemeId::Poseidon20W1NoOff => SchemePoseidon20W1NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon20W1Off10 => SchemePoseidon20W1Off10::LIFETIME,
        LeanSigSchemeId::Poseidon20W2NoOff => SchemePoseidon20W2NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon20W2Off10 => SchemePoseidon20W2Off10::LIFETIME,
        LeanSigSchemeId::Poseidon20W4NoOff => SchemePoseidon20W4NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon20W4Off10 => SchemePoseidon20W4Off10::LIFETIME,
        LeanSigSchemeId::Poseidon20W8NoOff => SchemePoseidon20W8NoOff::LIFETIME,
        LeanSigSchemeId::Poseidon20W8Off10 => SchemePoseidon20W8Off10::LIFETIME,
        LeanSigSchemeId::TopLevelTargetSumLifetime8Dim64Base8 => SchemeTopLevel8::LIFETIME,
        LeanSigSchemeId::CoreLargeBasePoseidon => SchemeCoreLargeBase::LIFETIME,
        LeanSigSchemeId::CoreLargeDimensionPoseidon => SchemeCoreLargeDimension::LIFETIME,
        LeanSigSchemeId::CoreTargetSumPoseidon => SchemeCoreTargetSum::LIFETIME,
    }
}

fn sign_with_scheme<T: SignatureScheme>(
    secret_key: &T::SecretKey,
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<T::Signature, String> {
    T::sign(secret_key, epoch, message).map_err(|e| format!("{e:?}"))
}

fn verify_with_scheme<T: SignatureScheme>(
    public_key: &T::PublicKey,
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
    signature: &T::Signature,
) -> bool {
    T::verify(public_key, epoch, message, signature)
}

fn advance_secret_key<T: SignatureScheme>(
    secret_key: &mut T::SecretKey,
    epoch: u32,
) -> Result<(), String> {
    let target_epoch = epoch as u64;
    let activation = secret_key.get_activation_interval();
    if !activation.contains(&target_epoch) {
        return Err(format!(
            "epoch {epoch} outside activation interval [{}, {})",
            activation.start, activation.end
        ));
    }

    loop {
        let prepared = secret_key.get_prepared_interval();
        if prepared.contains(&target_epoch) {
            return Ok(());
        }

        let prev_start = prepared.start;
        secret_key.advance_preparation();
        let next_start = secret_key.get_prepared_interval().start;
        if next_start == prev_start {
            return Err(format!("failed to advance prepared interval to epoch {epoch}"));
        }
    }
}

fn decode_signature_for_scheme<T: SignatureScheme>(bytes: &[u8]) -> Result<T::Signature, String> {
    <T as SignatureScheme>::Signature::from_bytes(bytes).map_err(|e| format!("{e:?}"))
}

fn seed_from_phrase(seed_phrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed_phrase.as_bytes());
    hasher.finalize().into()
}

unsafe fn c_string_from_ptr(ptr: *const c_char, what: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }

    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|s| s.to_owned())
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

unsafe fn message_from_ptr<'a>(message_ptr: *const u8) -> Result<&'a [u8; MESSAGE_LENGTH], String> {
    if message_ptr.is_null() {
        return Err("message pointer is null".to_string());
    }

    let message_slice = unsafe { slice::from_raw_parts(message_ptr, MESSAGE_LENGTH) };
    message_slice
        .try_into()
        .map_err(|_| format!("message pointer does not contain {MESSAGE_LENGTH} bytes"))
}

unsafe fn bytes_from_ptr<'a>(bytes_ptr: *const u8, bytes_len: usize) -> Result<&'a [u8], String> {
    if bytes_ptr.is_null() {
        return Err("input bytes pointer is null".to_string());
    }
    Ok(unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) })
}

impl PrivateKey {
    fn sign(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32) -> Result<Signature, String> {
        let inner = match &self.inner {
            AnySecretKey::SchemeDefault(sk) => {
                AnySignature::SchemeDefault(sign_with_scheme::<SchemeDefault>(sk, message, epoch)?)
            }
            AnySecretKey::SchemePoseidon18W1NoOff(sk) => AnySignature::SchemePoseidon18W1NoOff(
                sign_with_scheme::<SchemePoseidon18W1NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W1Off10(sk) => AnySignature::SchemePoseidon18W1Off10(
                sign_with_scheme::<SchemePoseidon18W1Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W2NoOff(sk) => AnySignature::SchemePoseidon18W2NoOff(
                sign_with_scheme::<SchemePoseidon18W2NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W2Off10(sk) => AnySignature::SchemePoseidon18W2Off10(
                sign_with_scheme::<SchemePoseidon18W2Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W4NoOff(sk) => AnySignature::SchemePoseidon18W4NoOff(
                sign_with_scheme::<SchemePoseidon18W4NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W4Off10(sk) => AnySignature::SchemePoseidon18W4Off10(
                sign_with_scheme::<SchemePoseidon18W4Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W8NoOff(sk) => AnySignature::SchemePoseidon18W8NoOff(
                sign_with_scheme::<SchemePoseidon18W8NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon18W8Off10(sk) => AnySignature::SchemePoseidon18W8Off10(
                sign_with_scheme::<SchemePoseidon18W8Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W1NoOff(sk) => AnySignature::SchemePoseidon20W1NoOff(
                sign_with_scheme::<SchemePoseidon20W1NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W1Off10(sk) => AnySignature::SchemePoseidon20W1Off10(
                sign_with_scheme::<SchemePoseidon20W1Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W2NoOff(sk) => AnySignature::SchemePoseidon20W2NoOff(
                sign_with_scheme::<SchemePoseidon20W2NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W2Off10(sk) => AnySignature::SchemePoseidon20W2Off10(
                sign_with_scheme::<SchemePoseidon20W2Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W4NoOff(sk) => AnySignature::SchemePoseidon20W4NoOff(
                sign_with_scheme::<SchemePoseidon20W4NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W4Off10(sk) => AnySignature::SchemePoseidon20W4Off10(
                sign_with_scheme::<SchemePoseidon20W4Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W8NoOff(sk) => AnySignature::SchemePoseidon20W8NoOff(
                sign_with_scheme::<SchemePoseidon20W8NoOff>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemePoseidon20W8Off10(sk) => AnySignature::SchemePoseidon20W8Off10(
                sign_with_scheme::<SchemePoseidon20W8Off10>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemeTopLevel8(sk) => {
                AnySignature::SchemeTopLevel8(sign_with_scheme::<SchemeTopLevel8>(sk, message, epoch)?)
            }
            AnySecretKey::SchemeCoreLargeBase(sk) => AnySignature::SchemeCoreLargeBase(
                sign_with_scheme::<SchemeCoreLargeBase>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemeCoreLargeDimension(sk) => AnySignature::SchemeCoreLargeDimension(
                sign_with_scheme::<SchemeCoreLargeDimension>(sk, message, epoch)?,
            ),
            AnySecretKey::SchemeCoreTargetSum(sk) => AnySignature::SchemeCoreTargetSum(
                sign_with_scheme::<SchemeCoreTargetSum>(sk, message, epoch)?,
            ),
        };

        Ok(Signature {
            scheme: self.scheme,
            inner,
        })
    }

    fn prepare_to_epoch(&mut self, epoch: u32) -> Result<(), String> {
        match &mut self.inner {
            AnySecretKey::SchemeDefault(sk) => advance_secret_key::<SchemeDefault>(sk, epoch),
            AnySecretKey::SchemePoseidon18W1NoOff(sk) => {
                advance_secret_key::<SchemePoseidon18W1NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W1Off10(sk) => {
                advance_secret_key::<SchemePoseidon18W1Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W2NoOff(sk) => {
                advance_secret_key::<SchemePoseidon18W2NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W2Off10(sk) => {
                advance_secret_key::<SchemePoseidon18W2Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W4NoOff(sk) => {
                advance_secret_key::<SchemePoseidon18W4NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W4Off10(sk) => {
                advance_secret_key::<SchemePoseidon18W4Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W8NoOff(sk) => {
                advance_secret_key::<SchemePoseidon18W8NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon18W8Off10(sk) => {
                advance_secret_key::<SchemePoseidon18W8Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W1NoOff(sk) => {
                advance_secret_key::<SchemePoseidon20W1NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W1Off10(sk) => {
                advance_secret_key::<SchemePoseidon20W1Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W2NoOff(sk) => {
                advance_secret_key::<SchemePoseidon20W2NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W2Off10(sk) => {
                advance_secret_key::<SchemePoseidon20W2Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W4NoOff(sk) => {
                advance_secret_key::<SchemePoseidon20W4NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W4Off10(sk) => {
                advance_secret_key::<SchemePoseidon20W4Off10>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W8NoOff(sk) => {
                advance_secret_key::<SchemePoseidon20W8NoOff>(sk, epoch)
            }
            AnySecretKey::SchemePoseidon20W8Off10(sk) => {
                advance_secret_key::<SchemePoseidon20W8Off10>(sk, epoch)
            }
            AnySecretKey::SchemeTopLevel8(sk) => advance_secret_key::<SchemeTopLevel8>(sk, epoch),
            AnySecretKey::SchemeCoreLargeBase(sk) => {
                advance_secret_key::<SchemeCoreLargeBase>(sk, epoch)
            }
            AnySecretKey::SchemeCoreLargeDimension(sk) => {
                advance_secret_key::<SchemeCoreLargeDimension>(sk, epoch)
            }
            AnySecretKey::SchemeCoreTargetSum(sk) => {
                advance_secret_key::<SchemeCoreTargetSum>(sk, epoch)
            }
        }
    }
}

impl PublicKey {
    fn verify(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32, signature: &Signature) -> bool {
        if self.scheme != signature.scheme {
            return false;
        }

        match (&self.inner, &signature.inner) {
            (AnyPublicKey::SchemeDefault(pk), AnySignature::SchemeDefault(sig)) => {
                verify_with_scheme::<SchemeDefault>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W1NoOff(pk), AnySignature::SchemePoseidon18W1NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon18W1NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W1Off10(pk), AnySignature::SchemePoseidon18W1Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon18W1Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W2NoOff(pk), AnySignature::SchemePoseidon18W2NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon18W2NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W2Off10(pk), AnySignature::SchemePoseidon18W2Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon18W2Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W4NoOff(pk), AnySignature::SchemePoseidon18W4NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon18W4NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W4Off10(pk), AnySignature::SchemePoseidon18W4Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon18W4Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W8NoOff(pk), AnySignature::SchemePoseidon18W8NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon18W8NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon18W8Off10(pk), AnySignature::SchemePoseidon18W8Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon18W8Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W1NoOff(pk), AnySignature::SchemePoseidon20W1NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon20W1NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W1Off10(pk), AnySignature::SchemePoseidon20W1Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon20W1Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W2NoOff(pk), AnySignature::SchemePoseidon20W2NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon20W2NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W2Off10(pk), AnySignature::SchemePoseidon20W2Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon20W2Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W4NoOff(pk), AnySignature::SchemePoseidon20W4NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon20W4NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W4Off10(pk), AnySignature::SchemePoseidon20W4Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon20W4Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W8NoOff(pk), AnySignature::SchemePoseidon20W8NoOff(sig)) => {
                verify_with_scheme::<SchemePoseidon20W8NoOff>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemePoseidon20W8Off10(pk), AnySignature::SchemePoseidon20W8Off10(sig)) => {
                verify_with_scheme::<SchemePoseidon20W8Off10>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemeTopLevel8(pk), AnySignature::SchemeTopLevel8(sig)) => {
                verify_with_scheme::<SchemeTopLevel8>(pk, message, epoch, sig)
            }
            (AnyPublicKey::SchemeCoreLargeBase(pk), AnySignature::SchemeCoreLargeBase(sig)) => {
                verify_with_scheme::<SchemeCoreLargeBase>(pk, message, epoch, sig)
            }
            (
                AnyPublicKey::SchemeCoreLargeDimension(pk),
                AnySignature::SchemeCoreLargeDimension(sig),
            ) => verify_with_scheme::<SchemeCoreLargeDimension>(pk, message, epoch, sig),
            (AnyPublicKey::SchemeCoreTargetSum(pk), AnySignature::SchemeCoreTargetSum(sig)) => {
                verify_with_scheme::<SchemeCoreTargetSum>(pk, message, epoch, sig)
            }
            _ => false,
        }
    }
}

impl Signature {
    fn to_bytes_vec(&self) -> Vec<u8> {
        match &self.inner {
            AnySignature::SchemeDefault(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W1NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W1Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W2NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W2Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W4NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W4Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W8NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon18W8Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W1NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W1Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W2NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W2Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W4NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W4Off10(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W8NoOff(sig) => sig.to_bytes(),
            AnySignature::SchemePoseidon20W8Off10(sig) => sig.to_bytes(),
            AnySignature::SchemeTopLevel8(sig) => sig.to_bytes(),
            AnySignature::SchemeCoreLargeBase(sig) => sig.to_bytes(),
            AnySignature::SchemeCoreLargeDimension(sig) => sig.to_bytes(),
            AnySignature::SchemeCoreTargetSum(sig) => sig.to_bytes(),
        }
    }

    fn from_bytes_for_scheme(scheme: LeanSigSchemeId, bytes: &[u8]) -> Result<Self, String> {
        let inner = match scheme {
            LeanSigSchemeId::TopLevelTargetSumLifetime18Dim64Base8 => AnySignature::SchemeDefault(
                decode_signature_for_scheme::<SchemeDefault>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W1NoOff => AnySignature::SchemePoseidon18W1NoOff(
                decode_signature_for_scheme::<SchemePoseidon18W1NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W1Off10 => AnySignature::SchemePoseidon18W1Off10(
                decode_signature_for_scheme::<SchemePoseidon18W1Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W2NoOff => AnySignature::SchemePoseidon18W2NoOff(
                decode_signature_for_scheme::<SchemePoseidon18W2NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W2Off10 => AnySignature::SchemePoseidon18W2Off10(
                decode_signature_for_scheme::<SchemePoseidon18W2Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W4NoOff => AnySignature::SchemePoseidon18W4NoOff(
                decode_signature_for_scheme::<SchemePoseidon18W4NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W4Off10 => AnySignature::SchemePoseidon18W4Off10(
                decode_signature_for_scheme::<SchemePoseidon18W4Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W8NoOff => AnySignature::SchemePoseidon18W8NoOff(
                decode_signature_for_scheme::<SchemePoseidon18W8NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon18W8Off10 => AnySignature::SchemePoseidon18W8Off10(
                decode_signature_for_scheme::<SchemePoseidon18W8Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W1NoOff => AnySignature::SchemePoseidon20W1NoOff(
                decode_signature_for_scheme::<SchemePoseidon20W1NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W1Off10 => AnySignature::SchemePoseidon20W1Off10(
                decode_signature_for_scheme::<SchemePoseidon20W1Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W2NoOff => AnySignature::SchemePoseidon20W2NoOff(
                decode_signature_for_scheme::<SchemePoseidon20W2NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W2Off10 => AnySignature::SchemePoseidon20W2Off10(
                decode_signature_for_scheme::<SchemePoseidon20W2Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W4NoOff => AnySignature::SchemePoseidon20W4NoOff(
                decode_signature_for_scheme::<SchemePoseidon20W4NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W4Off10 => AnySignature::SchemePoseidon20W4Off10(
                decode_signature_for_scheme::<SchemePoseidon20W4Off10>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W8NoOff => AnySignature::SchemePoseidon20W8NoOff(
                decode_signature_for_scheme::<SchemePoseidon20W8NoOff>(bytes)?,
            ),
            LeanSigSchemeId::Poseidon20W8Off10 => AnySignature::SchemePoseidon20W8Off10(
                decode_signature_for_scheme::<SchemePoseidon20W8Off10>(bytes)?,
            ),
            LeanSigSchemeId::TopLevelTargetSumLifetime8Dim64Base8 => {
                AnySignature::SchemeTopLevel8(decode_signature_for_scheme::<SchemeTopLevel8>(bytes)?)
            }
            LeanSigSchemeId::CoreLargeBasePoseidon => AnySignature::SchemeCoreLargeBase(
                decode_signature_for_scheme::<SchemeCoreLargeBase>(bytes)?,
            ),
            LeanSigSchemeId::CoreLargeDimensionPoseidon => AnySignature::SchemeCoreLargeDimension(
                decode_signature_for_scheme::<SchemeCoreLargeDimension>(bytes)?,
            ),
            LeanSigSchemeId::CoreTargetSumPoseidon => AnySignature::SchemeCoreTargetSum(
                decode_signature_for_scheme::<SchemeCoreTargetSum>(bytes)?,
            ),
        };

        Ok(Self { scheme, inner })
    }
}

impl KeyPair {
    fn generate(
        scheme: LeanSigSchemeId,
        rng: &mut StdRng,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> Self {
        match scheme {
            LeanSigSchemeId::TopLevelTargetSumLifetime18Dim64Base8 => {
                let (pk, sk) = SchemeDefault::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemeDefault(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemeDefault(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W1NoOff => {
                let (pk, sk) = SchemePoseidon18W1NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W1NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W1NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W1Off10 => {
                let (pk, sk) = SchemePoseidon18W1Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W1Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W1Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W2NoOff => {
                let (pk, sk) = SchemePoseidon18W2NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W2NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W2NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W2Off10 => {
                let (pk, sk) = SchemePoseidon18W2Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W2Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W2Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W4NoOff => {
                let (pk, sk) = SchemePoseidon18W4NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W4NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W4NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W4Off10 => {
                let (pk, sk) = SchemePoseidon18W4Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W4Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W4Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W8NoOff => {
                let (pk, sk) = SchemePoseidon18W8NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W8NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W8NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon18W8Off10 => {
                let (pk, sk) = SchemePoseidon18W8Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon18W8Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon18W8Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W1NoOff => {
                let (pk, sk) = SchemePoseidon20W1NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W1NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W1NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W1Off10 => {
                let (pk, sk) = SchemePoseidon20W1Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W1Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W1Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W2NoOff => {
                let (pk, sk) = SchemePoseidon20W2NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W2NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W2NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W2Off10 => {
                let (pk, sk) = SchemePoseidon20W2Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W2Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W2Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W4NoOff => {
                let (pk, sk) = SchemePoseidon20W4NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W4NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W4NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W4Off10 => {
                let (pk, sk) = SchemePoseidon20W4Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W4Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W4Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W8NoOff => {
                let (pk, sk) = SchemePoseidon20W8NoOff::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W8NoOff(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W8NoOff(sk),
                    },
                }
            }
            LeanSigSchemeId::Poseidon20W8Off10 => {
                let (pk, sk) = SchemePoseidon20W8Off10::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemePoseidon20W8Off10(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemePoseidon20W8Off10(sk),
                    },
                }
            }
            LeanSigSchemeId::TopLevelTargetSumLifetime8Dim64Base8 => {
                let (pk, sk) = SchemeTopLevel8::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemeTopLevel8(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemeTopLevel8(sk),
                    },
                }
            }
            LeanSigSchemeId::CoreLargeBasePoseidon => {
                let (pk, sk) = SchemeCoreLargeBase::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemeCoreLargeBase(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemeCoreLargeBase(sk),
                    },
                }
            }
            LeanSigSchemeId::CoreLargeDimensionPoseidon => {
                let (pk, sk) =
                    SchemeCoreLargeDimension::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemeCoreLargeDimension(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemeCoreLargeDimension(sk),
                    },
                }
            }
            LeanSigSchemeId::CoreTargetSumPoseidon => {
                let (pk, sk) = SchemeCoreTargetSum::key_gen(rng, activation_epoch, num_active_epochs);
                Self {
                    scheme,
                    public_key: PublicKey {
                        scheme,
                        inner: AnyPublicKey::SchemeCoreTargetSum(pk),
                    },
                    private_key: PrivateKey {
                        scheme,
                        inner: AnySecretKey::SchemeCoreTargetSum(sk),
                    },
                }
            }
        }
    }

    fn sign(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32) -> Result<Signature, String> {
        self.private_key.sign(message, epoch)
    }

    fn verify(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32, signature: &Signature) -> bool {
        if self.scheme != signature.scheme {
            return false;
        }
        self.public_key.verify(message, epoch, signature)
    }

    fn prepare_to_epoch(&mut self, epoch: u32) -> Result<(), String> {
        self.private_key.prepare_to_epoch(epoch)
    }
}

#[no_mangle]
pub extern "C" fn leansig_lifetime() -> u64 {
    scheme_lifetime(DEFAULT_SCHEME_ID)
}

#[no_mangle]
pub extern "C" fn leansig_message_length() -> usize {
    MESSAGE_LENGTH
}

#[no_mangle]
pub extern "C" fn leansig_scheme_lifetime_v2(scheme_id: u32) -> u64 {
    match parse_scheme_id(scheme_id) {
        Ok(scheme) => {
            clear_last_error();
            scheme_lifetime(scheme)
        }
        Err(err) => {
            set_last_error(err);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_generate_v2(
    scheme_id: u32,
    seed_phrase: *const c_char,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut KeyPair {
    let scheme = match parse_scheme_id(scheme_id) {
        Ok(scheme) => scheme,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let seed_phrase = match unsafe { c_string_from_ptr(seed_phrase, "seed phrase") } {
        Ok(seed_phrase) => seed_phrase,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let seed = seed_from_phrase(&seed_phrase);
    let mut rng = <StdRng as SeedableRng>::from_seed(seed);
    let keypair = KeyPair::generate(scheme, &mut rng, activation_epoch, num_active_epochs);

    clear_last_error();
    Box::into_raw(Box::new(keypair))
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_prepare_to_epoch_v2(
    keypair: *mut KeyPair,
    epoch: u32,
) -> i32 {
    if keypair.is_null() {
        set_last_error("keypair pointer is null");
        return 0;
    }

    let keypair_ref = unsafe { &mut *keypair };
    match keypair_ref.prepare_to_epoch(epoch) {
        Ok(()) => {
            clear_last_error();
            1
        }
        Err(err) => {
            set_last_error(err);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_sign_v2(
    keypair: *const KeyPair,
    message_ptr: *const u8,
    epoch: u32,
) -> *mut Signature {
    if keypair.is_null() {
        set_last_error("keypair pointer is null");
        return ptr::null_mut();
    }

    let message = match unsafe { message_from_ptr(message_ptr) } {
        Ok(message) => message,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let keypair_ref = unsafe { &*keypair };
    match keypair_ref.sign(message, epoch) {
        Ok(signature) => {
            clear_last_error();
            Box::into_raw(Box::new(signature))
        }
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_verify_v2(
    keypair: *const KeyPair,
    message_ptr: *const u8,
    epoch: u32,
    signature: *const Signature,
) -> i32 {
    if keypair.is_null() || signature.is_null() {
        set_last_error("keypair or signature pointer is null");
        return -1;
    }

    let message = match unsafe { message_from_ptr(message_ptr) } {
        Ok(message) => message,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };

    let keypair_ref = unsafe { &*keypair };
    let signature_ref = unsafe { &*signature };

    clear_last_error();
    if keypair_ref.verify(message, epoch, signature_ref) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_signature_to_bytes_len_v2(signature: *const Signature) -> usize {
    if signature.is_null() {
        set_last_error("signature pointer is null");
        return 0;
    }

    let signature_ref = unsafe { &*signature };
    let len = signature_ref.to_bytes_vec().len();
    clear_last_error();
    len
}

#[no_mangle]
pub unsafe extern "C" fn leansig_signature_to_bytes_copy_v2(
    signature: *const Signature,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if signature.is_null() {
        set_last_error("signature pointer is null");
        return 0;
    }
    if out.is_null() || out_len == 0 {
        set_last_error("output buffer is null or empty");
        return 0;
    }

    let signature_ref = unsafe { &*signature };
    let bytes = signature_ref.to_bytes_vec();
    let copy_len = bytes.len().min(out_len);

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len);
    }

    if copy_len < bytes.len() {
        set_last_error("output buffer too small for signature bytes");
    } else {
        clear_last_error();
    }

    copy_len
}

#[no_mangle]
pub unsafe extern "C" fn leansig_signature_from_bytes_v2(
    scheme_id: u32,
    bytes_ptr: *const u8,
    bytes_len: usize,
) -> *mut Signature {
    let scheme = match parse_scheme_id(scheme_id) {
        Ok(scheme) => scheme,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let bytes = match unsafe { bytes_from_ptr(bytes_ptr, bytes_len) } {
        Ok(bytes) => bytes,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    match Signature::from_bytes_for_scheme(scheme, bytes) {
        Ok(signature) => {
            clear_last_error();
            Box::into_raw(Box::new(signature))
        }
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed_phrase: *const c_char,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut KeyPair {
    unsafe {
        leansig_keypair_generate_v2(
            DEFAULT_SCHEME_ID as u32,
            seed_phrase,
            activation_epoch,
            num_active_epochs,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_free(keypair: *mut KeyPair) {
    if !keypair.is_null() {
        unsafe {
            let _ = Box::from_raw(keypair);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_get_public_key(
    keypair: *const KeyPair,
) -> *const PublicKey {
    if keypair.is_null() {
        return ptr::null();
    }
    unsafe { &(*keypair).public_key }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_keypair_get_private_key(
    keypair: *const KeyPair,
) -> *const PrivateKey {
    if keypair.is_null() {
        return ptr::null();
    }
    unsafe { &(*keypair).private_key }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_sign(
    private_key: *const PrivateKey,
    message_ptr: *const u8,
    epoch: u32,
) -> *mut Signature {
    if private_key.is_null() {
        set_last_error("private key pointer is null");
        return ptr::null_mut();
    }

    let message = match unsafe { message_from_ptr(message_ptr) } {
        Ok(message) => message,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let private_key_ref = unsafe { &*private_key };
    match private_key_ref.sign(message, epoch) {
        Ok(signature) => {
            clear_last_error();
            Box::into_raw(Box::new(signature))
        }
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_signature_free(signature: *mut Signature) {
    if !signature.is_null() {
        unsafe {
            let _ = Box::from_raw(signature);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_verify(
    public_key: *const PublicKey,
    message_ptr: *const u8,
    epoch: u32,
    signature: *const Signature,
) -> i32 {
    if public_key.is_null() || signature.is_null() {
        set_last_error("public key or signature pointer is null");
        return -1;
    }

    let message = match unsafe { message_from_ptr(message_ptr) } {
        Ok(message) => message,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };

    let public_key_ref = unsafe { &*public_key };
    let signature_ref = unsafe { &*signature };

    clear_last_error();
    if public_key_ref.verify(message, epoch, signature_ref) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn leansig_last_error_len() -> usize {
    if let Ok(guard) = error_storage().lock() {
        guard.len().saturating_sub(1)
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn leansig_last_error_copy(out: *mut u8, out_len: usize) -> usize {
    if out.is_null() || out_len == 0 {
        return 0;
    }

    let guard = match error_storage().lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    let copy_len = guard.len().min(out_len);

    unsafe {
        ptr::copy_nonoverlapping(guard.as_ptr(), out, copy_len);
    }

    if copy_len == out_len {
        unsafe {
            *out.add(out_len - 1) = 0;
        }
        out_len.saturating_sub(1)
    } else {
        copy_len.saturating_sub(1)
    }
}
