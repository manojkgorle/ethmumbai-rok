use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::error::{RokError, Result};
use crate::keys::spend::SpendKeyPair;

/// Sign arbitrary data with a spend key (Ed25519).
pub fn sign(spend_key: &SpendKeyPair, data: &[u8]) -> [u8; 64] {
    let signature: Signature = spend_key.signing_key().sign(data);
    signature.to_bytes()
}

/// Verify a signature against a spend public key.
pub fn verify(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<()> {
    let signature =
        Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(data, &signature)
        .map_err(|_| RokError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let data = b"hello world";
        let sig = sign(&spend, data);
        assert!(verify(&spend.verifying_key(), data, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let spend1 = SpendKeyPair::from_seed(&[1u8; 32]);
        let spend2 = SpendKeyPair::from_seed(&[2u8; 32]);
        let data = b"hello";
        let sig = sign(&spend1, data);
        assert!(verify(&spend2.verifying_key(), data, &sig).is_err());
    }

    #[test]
    fn test_verify_tampered_data_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let data = b"hello";
        let sig = sign(&spend, data);
        assert!(verify(&spend.verifying_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let data = b"hello";
        let mut sig = sign(&spend, data);
        sig[0] ^= 0xff;
        assert!(verify(&spend.verifying_key(), data, &sig).is_err());
    }
}
