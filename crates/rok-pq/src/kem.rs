use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand_core::CryptoRngCore;

/// An ML-KEM-768 key pair for post-quantum key encapsulation.
///
/// ML-KEM-768 provides ~128-bit post-quantum security level,
/// suitable for general-purpose use.
pub struct PqKeyPair {
    decapsulation_key: <MlKem768 as KemCore>::DecapsulationKey,
    encapsulation_key: <MlKem768 as KemCore>::EncapsulationKey,
}

impl PqKeyPair {
    /// Generate a new ML-KEM-768 key pair.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let (dk, ek) = MlKem768::generate(rng);
        PqKeyPair {
            decapsulation_key: dk,
            encapsulation_key: ek,
        }
    }

    /// The encapsulation (public) key — share this with encryptors.
    pub fn encapsulation_key(&self) -> &<MlKem768 as KemCore>::EncapsulationKey {
        &self.encapsulation_key
    }

    /// The decapsulation (private) key — keep this secret.
    pub fn decapsulation_key(&self) -> &<MlKem768 as KemCore>::DecapsulationKey {
        &self.decapsulation_key
    }
}

/// Encapsulate: produce a shared secret and ciphertext.
///
/// The sender calls this with the recipient's encapsulation key.
/// Returns (shared_secret_bytes, ciphertext_bytes).
pub fn encapsulate(
    rng: &mut impl CryptoRngCore,
    ek: &<MlKem768 as KemCore>::EncapsulationKey,
) -> (Vec<u8>, Vec<u8>) {
    let (ct, ss) = ek.encapsulate(rng).unwrap();
    // Convert hybrid_array::Array types to Vec<u8>
    let ss_bytes: Vec<u8> = ss.as_slice().to_vec();
    let ct_bytes: Vec<u8> = ct.as_slice().to_vec();
    (ss_bytes, ct_bytes)
}

/// Decapsulate: recover the shared secret from a ciphertext.
///
/// The recipient calls this with their decapsulation key.
/// Returns the shared_secret_bytes.
pub fn decapsulate(
    dk: &<MlKem768 as KemCore>::DecapsulationKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, rok_core::error::RokError> {
    // Reconstruct the ciphertext Array from the byte slice
    let ct: ml_kem::Ciphertext<MlKem768> = ciphertext.try_into().map_err(|_| {
        rok_core::error::RokError::DecryptionError(format!(
            "invalid ML-KEM ciphertext length: {}",
            ciphertext.len()
        ))
    })?;

    let ss = dk.decapsulate(&ct).map_err(|_| {
        rok_core::error::RokError::DecryptionError("ML-KEM decapsulation failed".into())
    })?;

    Ok(ss.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_encapsulate_decapsulate_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = PqKeyPair::generate(&mut rng);

        let (ss_sender, ct) = encapsulate(&mut rng, keypair.encapsulation_key());
        let ss_recipient = decapsulate(keypair.decapsulation_key(), &ct).unwrap();

        assert_eq!(ss_sender, ss_recipient);
        assert_eq!(ss_sender.len(), 32); // ML-KEM-768 shared secret is 32 bytes
    }

    #[test]
    fn test_different_keypairs_different_shared_secrets() {
        let mut rng = rand::thread_rng();
        let kp1 = PqKeyPair::generate(&mut rng);
        let kp2 = PqKeyPair::generate(&mut rng);

        let (ss1, _) = encapsulate(&mut rng, kp1.encapsulation_key());
        let (ss2, _) = encapsulate(&mut rng, kp2.encapsulation_key());

        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_wrong_key_decapsulation_yields_different_secret() {
        let mut rng = rand::thread_rng();
        let kp1 = PqKeyPair::generate(&mut rng);
        let kp2 = PqKeyPair::generate(&mut rng);

        let (ss_sender, ct) = encapsulate(&mut rng, kp1.encapsulation_key());
        // ML-KEM is IND-CCA2: wrong key produces a pseudorandom (different) shared secret
        let ss_wrong = decapsulate(kp2.decapsulation_key(), &ct).unwrap();
        assert_ne!(ss_sender, ss_wrong);
    }
}
