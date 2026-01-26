use rand::rngs::OsRng;
use std::ptr;

use leansig::signature::generalized_xmss::Instance;
use leansig::signature::SignatureScheme;

#[repr(C)]
pub struct LeanSigHandle {
    inner: Instance,
}

#[no_mangle]
pub extern "C" fn leansig_new() -> *mut LeanSigHandle {
    let scheme = Instance {};
    Box::into_raw(Box::new(LeanSigHandle { inner: scheme }))
}

#[no_mangle]
pub extern "C" fn leansig_free(h: *mut LeanSigHandle) {
    if h.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(h));
    }
}

#[no_mangle]
pub extern "C" fn leansig_public_key_len(h: *mut LeanSigHandle) -> usize {
    if h.is_null() {
        return 0;
    }
    unsafe { (*h).inner.public_key_len() }
}

#[no_mangle]
pub extern "C" fn leansig_secret_key_len(h: *mut LeanSigHandle) -> usize {
    if h.is_null() {
        return 0;
    }
    unsafe { (*h).inner.secret_key_len() }
}

#[no_mangle]
pub extern "C" fn leansig_signature_len(h: *mut LeanSigHandle) -> usize {
    if h.is_null() {
        return 0;
    }
    unsafe { (*h).inner.signature_len() }
}
