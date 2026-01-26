use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use leansig::signature::SignatureScheme;

// Type alias for the concrete signature scheme instance
type SigScheme = SIGTopLevelTargetSumLifetime18Dim64Base8;

/// Returns the lifetime of the signature scheme
#[no_mangle]
pub extern "C" fn leansig_lifetime() -> u64 {
    SigScheme::LIFETIME
}
