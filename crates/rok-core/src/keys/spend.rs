use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::derive;
use crate::keys::key_id::KeyId;
use crate::keys::read::ReadKeyPair;
use crate::keys::scope::Scope;

/// The spend key pair — the root of trust in the ROK system.
///
/// Uses Ed25519 for signing. The spend key holder has full authority:
/// - Sign data and envelopes (prove authenticity)
/// - Derive all read keys in the hierarchy
/// - Encrypt data for any scope
///
/// The secret key (seed) must NEVER leave the owner's control.
pub struct SpendKeyPair {
    signing_key: SigningKey,
}

// Manual Zeroize since SigningKey stores a seed internally
impl Drop for SpendKeyPair {
    fn drop(&mut self) {
        // SigningKey internally zeroizes on drop in ed25519-dalek 2.x
    }
}

impl SpendKeyPair {
    /// Generate a new random spend key pair.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let signing_key = SigningKey::generate(rng);
        SpendKeyPair { signing_key }
    }

    /// Recover from a 32-byte seed (for backup/restore).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        SpendKeyPair { signing_key }
    }

    /// Export the seed bytes (for backup). Caller must secure this.
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// The public verifying key (the user's public identity).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Reference to the signing key (used internally for signing envelopes).
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Derive the root read key at scope "/".
    ///
    /// This is the top of the read key hierarchy. From this root,
    /// all descendant read keys can be derived.
    pub fn derive_root_read_key(&self) -> ReadKeyPair {
        let mut seed = self.signing_key.to_bytes();
        let read_secret_bytes = derive::derive_root_read_secret(&seed);
        seed.zeroize();

        ReadKeyPair::from_secret_bytes(read_secret_bytes, Scope::root(), None)
    }

    /// Compute the KeyId for this spend key's public key.
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_bytes(self.verifying_key().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_seed_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = SpendKeyPair::generate(&mut rng);
        let seed = key.seed();
        let restored = SpendKeyPair::from_seed(&seed);

        assert_eq!(key.verifying_key(), restored.verifying_key());
    }

    #[test]
    fn test_key_id_deterministic() {
        let key = SpendKeyPair::from_seed(&[42u8; 32]);
        let id1 = key.key_id();
        let id2 = key.key_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_root_read_key_deterministic() {
        let key = SpendKeyPair::from_seed(&[42u8; 32]);
        let root1 = key.derive_root_read_key();
        let root2 = key.derive_root_read_key();

        assert_eq!(root1.key_id(), root2.key_id());
        assert_eq!(root1.scope(), root2.scope());
    }

    #[test]
    fn test_different_spend_keys_different_read_keys() {
        let key1 = SpendKeyPair::from_seed(&[1u8; 32]);
        let key2 = SpendKeyPair::from_seed(&[2u8; 32]);

        let root1 = key1.derive_root_read_key();
        let root2 = key2.derive_root_read_key();

        assert_ne!(root1.key_id(), root2.key_id());
    }
}
