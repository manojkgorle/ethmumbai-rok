use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, RokError};
use crate::keys::key_id::KeyId;
use crate::keys::scope::Scope;

/// Domain separation tag for spend -> root read derivation.
const DOMAIN_SPEND_TO_ROOT: &[u8] = b"rok-v1-spend-to-root-read";

/// Domain separation tag for read -> child read derivation.
const DOMAIN_READ_CHILD: &[u8] = b"rok-v1-read-child-derive";

/// Domain separation tag for ECDH shared secret -> wrapping key.
const DOMAIN_KEY_WRAP: &[u8] = b"rok-v1-key-wrap";

/// Domain separation tag for hybrid X25519+ML-KEM secret combination.
const DOMAIN_HYBRID_COMBINE: &[u8] = b"rok-v1-hybrid-combine";

/// Derive the root read key secret from a spend key secret.
///
/// Uses HKDF-SHA256 with the spend secret as IKM,
/// domain tag as salt, and scope "/" as info.
pub(crate) fn derive_root_read_secret(spend_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_SPEND_TO_ROOT), spend_secret);
    let mut output = [0u8; 32];
    hk.expand(b"/", &mut output)
        .expect("HKDF-SHA256 expand to 32 bytes should never fail");
    output
}

/// Derive a child read key secret from a parent read key secret.
///
/// The derivation is step-wise: to derive `/finance/q1` from root,
/// first derive `/finance`, then `/finance/q1` from that.
///
/// `child_scope` must be a direct child (one segment deeper) or a
/// transitive descendant of `parent_scope`. For direct derivation,
/// pass the immediate child scope.
pub(crate) fn derive_child_read_secret(
    parent_secret: &[u8; 32],
    parent_scope: &Scope,
    child_scope: &Scope,
) -> Result<[u8; 32]> {
    if !parent_scope.is_ancestor_of(child_scope) {
        return Err(RokError::DerivationError(format!(
            "scope '{}' is not a descendant of '{}'",
            child_scope, parent_scope
        )));
    }

    if parent_scope == child_scope {
        return Err(RokError::DerivationError(
            "child scope must differ from parent scope".into(),
        ));
    }

    // Walk the scope tree from parent to child, deriving one level at a time
    let parent_components = parent_scope.components();
    let child_components = child_scope.components();

    let mut current_secret = *parent_secret;

    for i in parent_components.len()..child_components.len() {
        // Build the scope path for this intermediate level
        let intermediate_path = format!("/{}", child_components[..=i].join("/"));

        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_READ_CHILD), &current_secret);
        let mut next_secret = [0u8; 32];
        hk.expand(intermediate_path.as_bytes(), &mut next_secret)
            .expect("HKDF-SHA256 expand to 32 bytes should never fail");

        current_secret.zeroize();
        current_secret = next_secret;
    }

    Ok(current_secret)
}

/// Derive a wrapping key from an ECDH shared secret and a recipient's key ID.
///
/// Used to wrap the per-envelope data key for a specific recipient.
pub(crate) fn derive_wrapping_key(shared_secret: &[u8; 32], key_id: &KeyId) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_KEY_WRAP), shared_secret);
    let mut output = [0u8; 32];
    hk.expand(key_id.as_bytes(), &mut output)
        .expect("HKDF-SHA256 expand to 32 bytes should never fail");
    output
}

/// Combine an X25519 shared secret with an ML-KEM shared secret for hybrid mode.
///
/// The combined secret is secure as long as at least one of the two
/// underlying shared secrets remains uncompromised.
pub fn combine_hybrid_secrets(x25519_shared: &[u8; 32], mlkem_shared: &[u8]) -> [u8; 32] {
    let mut combined_ikm = Vec::with_capacity(32 + mlkem_shared.len());
    combined_ikm.extend_from_slice(x25519_shared);
    combined_ikm.extend_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_HYBRID_COMBINE), &combined_ikm);
    let mut output = [0u8; 32];
    hk.expand(&[], &mut output)
        .expect("HKDF-SHA256 expand to 32 bytes should never fail");

    combined_ikm.zeroize();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_derivation_deterministic() {
        let spend_secret = [42u8; 32];
        let root1 = derive_root_read_secret(&spend_secret);
        let root2 = derive_root_read_secret(&spend_secret);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_root_derivation_different_inputs() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let root1 = derive_root_read_secret(&secret1);
        let root2 = derive_root_read_secret(&secret2);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_child_derivation_deterministic() {
        let parent_secret = [99u8; 32];
        let parent_scope = Scope::root();
        let child_scope = Scope::new("/finance").unwrap();

        let child1 = derive_child_read_secret(&parent_secret, &parent_scope, &child_scope).unwrap();
        let child2 = derive_child_read_secret(&parent_secret, &parent_scope, &child_scope).unwrap();
        assert_eq!(child1, child2);
    }

    #[test]
    fn test_sibling_independence() {
        let parent_secret = [99u8; 32];
        let parent_scope = Scope::root();
        let finance = Scope::new("/finance").unwrap();
        let legal = Scope::new("/legal").unwrap();

        let finance_secret =
            derive_child_read_secret(&parent_secret, &parent_scope, &finance).unwrap();
        let legal_secret = derive_child_read_secret(&parent_secret, &parent_scope, &legal).unwrap();
        assert_ne!(finance_secret, legal_secret);
    }

    #[test]
    fn test_stepwise_derivation() {
        // Deriving /finance/q1 from root should produce the same result
        // whether we do it in one step or two
        let root_secret = [77u8; 32];
        let root_scope = Scope::root();
        let finance_scope = Scope::new("/finance").unwrap();
        let finance_q1_scope = Scope::new("/finance/q1").unwrap();

        // One step: root -> /finance/q1
        let direct =
            derive_child_read_secret(&root_secret, &root_scope, &finance_q1_scope).unwrap();

        // Two steps: root -> /finance -> /finance/q1
        let finance_secret =
            derive_child_read_secret(&root_secret, &root_scope, &finance_scope).unwrap();
        let stepwise =
            derive_child_read_secret(&finance_secret, &finance_scope, &finance_q1_scope).unwrap();

        assert_eq!(direct, stepwise);
    }

    #[test]
    fn test_non_ancestor_scope_rejected() {
        let parent_secret = [1u8; 32];
        let finance = Scope::new("/finance").unwrap();
        let legal = Scope::new("/legal").unwrap();

        assert!(derive_child_read_secret(&parent_secret, &finance, &legal).is_err());
    }

    #[test]
    fn test_same_scope_rejected() {
        let secret = [1u8; 32];
        let scope = Scope::new("/finance").unwrap();
        assert!(derive_child_read_secret(&secret, &scope, &scope).is_err());
    }

    #[test]
    fn test_wrapping_key_deterministic() {
        let shared = [55u8; 32];
        let key_id = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let wk1 = derive_wrapping_key(&shared, &key_id);
        let wk2 = derive_wrapping_key(&shared, &key_id);
        assert_eq!(wk1, wk2);
    }

    #[test]
    fn test_wrapping_key_different_key_ids() {
        let shared = [55u8; 32];
        let id1 = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let id2 = KeyId::from_bytes([8, 7, 6, 5, 4, 3, 2, 1]);
        let wk1 = derive_wrapping_key(&shared, &id1);
        let wk2 = derive_wrapping_key(&shared, &id2);
        assert_ne!(wk1, wk2);
    }

    #[test]
    fn test_hybrid_combine_deterministic() {
        let x25519 = [10u8; 32];
        let mlkem = [20u8; 32];
        let c1 = combine_hybrid_secrets(&x25519, &mlkem);
        let c2 = combine_hybrid_secrets(&x25519, &mlkem);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_hybrid_combine_different_from_components() {
        let x25519 = [10u8; 32];
        let mlkem = [20u8; 32];
        let combined = combine_hybrid_secrets(&x25519, &mlkem);
        // Combined should not equal either component
        assert_ne!(combined, x25519);
        assert_ne!(combined, mlkem);
    }
}
