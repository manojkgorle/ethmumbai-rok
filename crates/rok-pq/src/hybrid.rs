use ml_kem::{KemCore, MlKem768};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use rok_core::derive::combine_hybrid_secrets;
use rok_core::error::Result;
use rok_core::keys::key_id::KeyId;

use crate::kem;

/// A recipient with both classical (X25519) and post-quantum (ML-KEM) public keys.
pub struct HybridRecipient {
    pub x25519_public: X25519PublicKey,
    pub mlkem_encapsulation_key: <MlKem768 as KemCore>::EncapsulationKey,
    pub key_id: KeyId,
}

/// Result of hybrid encapsulation for one recipient.
pub struct HybridEncapsulation {
    /// The combined shared secret (X25519 + ML-KEM via HKDF).
    pub combined_shared_secret: [u8; 32],
    /// ML-KEM ciphertext bytes (to include in the envelope).
    pub mlkem_ciphertext: Vec<u8>,
}

/// Perform hybrid encapsulation for a recipient.
///
/// Combines X25519 ECDH with ML-KEM-768 encapsulation.
/// The resulting shared secret is secure as long as at least one
/// of X25519 or ML-KEM remains unbroken.
pub fn hybrid_encapsulate(
    rng: &mut impl CryptoRngCore,
    recipient: &HybridRecipient,
    ephemeral_x25519_secret: &StaticSecret,
) -> HybridEncapsulation {
    // 1. X25519 ECDH
    let x25519_shared = ephemeral_x25519_secret.diffie_hellman(&recipient.x25519_public);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(x25519_shared.as_bytes());

    // 2. ML-KEM encapsulation
    let (mlkem_ss, mlkem_ct) = kem::encapsulate(rng, &recipient.mlkem_encapsulation_key);

    // 3. Combine via HKDF
    let combined = combine_hybrid_secrets(&x25519_bytes, &mlkem_ss);
    x25519_bytes.zeroize();

    HybridEncapsulation {
        combined_shared_secret: combined,
        mlkem_ciphertext: mlkem_ct,
    }
}

/// Perform hybrid decapsulation.
///
/// Reverses the hybrid encapsulation: recovers the combined shared secret
/// from the X25519 ECDH and ML-KEM decapsulation.
pub fn hybrid_decapsulate(
    x25519_secret: &StaticSecret,
    ephemeral_x25519_public: &X25519PublicKey,
    mlkem_decapsulation_key: &<MlKem768 as KemCore>::DecapsulationKey,
    mlkem_ciphertext: &[u8],
) -> Result<[u8; 32]> {
    // 1. X25519 ECDH
    let x25519_shared = x25519_secret.diffie_hellman(ephemeral_x25519_public);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(x25519_shared.as_bytes());

    // 2. ML-KEM decapsulation
    let mlkem_ss = kem::decapsulate(mlkem_decapsulation_key, mlkem_ciphertext)?;

    // 3. Combine via HKDF
    let combined = combine_hybrid_secrets(&x25519_bytes, &mlkem_ss);
    x25519_bytes.zeroize();

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::PqKeyPair;
    use rand::Rng;

    #[test]
    fn test_hybrid_roundtrip() {
        let mut rng = rand::thread_rng();

        // Recipient generates both key types
        let pq_keypair = PqKeyPair::generate(&mut rng);

        let mut x25519_secret_bytes = [0u8; 32];
        rng.fill(&mut x25519_secret_bytes);
        let x25519_secret = StaticSecret::from(x25519_secret_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let recipient = HybridRecipient {
            x25519_public,
            mlkem_encapsulation_key: pq_keypair.encapsulation_key().clone(),
            key_id: KeyId::from_public_bytes(x25519_public.as_bytes()),
        };

        // Sender: ephemeral key + hybrid encapsulate
        let mut eph_secret_bytes = [0u8; 32];
        rng.fill(&mut eph_secret_bytes);
        let eph_secret = StaticSecret::from(eph_secret_bytes);
        let eph_public = X25519PublicKey::from(&eph_secret);

        let encap = hybrid_encapsulate(&mut rng, &recipient, &eph_secret);

        // Recipient: hybrid decapsulate
        let decap_secret = hybrid_decapsulate(
            &x25519_secret,
            &eph_public,
            pq_keypair.decapsulation_key(),
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        assert_eq!(encap.combined_shared_secret, decap_secret);
    }

    #[test]
    fn test_hybrid_wrong_x25519_key_fails() {
        let mut rng = rand::thread_rng();

        let pq_keypair = PqKeyPair::generate(&mut rng);

        let mut x25519_bytes = [0u8; 32];
        rng.fill(&mut x25519_bytes);
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let recipient = HybridRecipient {
            x25519_public,
            mlkem_encapsulation_key: pq_keypair.encapsulation_key().clone(),
            key_id: KeyId::from_public_bytes(x25519_public.as_bytes()),
        };

        let mut eph_bytes = [0u8; 32];
        rng.fill(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        let eph_public = X25519PublicKey::from(&eph_secret);

        let encap = hybrid_encapsulate(&mut rng, &recipient, &eph_secret);

        // Use a wrong X25519 key for decapsulation
        let mut wrong_bytes = [0u8; 32];
        rng.fill(&mut wrong_bytes);
        let wrong_secret = StaticSecret::from(wrong_bytes);

        let decap = hybrid_decapsulate(
            &wrong_secret,
            &eph_public,
            pq_keypair.decapsulation_key(),
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        // Should produce a different shared secret
        assert_ne!(encap.combined_shared_secret, decap);
    }

    #[test]
    fn test_hybrid_wrong_pq_key_fails() {
        let mut rng = rand::thread_rng();

        let pq_keypair = PqKeyPair::generate(&mut rng);
        let wrong_pq = PqKeyPair::generate(&mut rng);

        let mut x25519_bytes = [0u8; 32];
        rng.fill(&mut x25519_bytes);
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let recipient = HybridRecipient {
            x25519_public,
            mlkem_encapsulation_key: pq_keypair.encapsulation_key().clone(),
            key_id: KeyId::from_public_bytes(x25519_public.as_bytes()),
        };

        let mut eph_bytes = [0u8; 32];
        rng.fill(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        let eph_public = X25519PublicKey::from(&eph_secret);

        let encap = hybrid_encapsulate(&mut rng, &recipient, &eph_secret);

        // Use wrong PQ key for decapsulation
        let decap = hybrid_decapsulate(
            &x25519_secret,
            &eph_public,
            wrong_pq.decapsulation_key(),
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        // Should produce a different shared secret
        assert_ne!(encap.combined_shared_secret, decap);
    }
}
