use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use rok_core::encrypt::{
    decrypt_payload, encrypt_payload, unwrap_data_key, wrap_data_key, AccessMode, Algorithm,
};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::error::{Result, RokError};
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

use crate::hybrid::{hybrid_decapsulate, hybrid_encapsulate, HybridRecipient};
use crate::pq_derive::derive_pq_keypair;

/// Encrypt plaintext using hybrid X25519 + ML-KEM-768 + ChaCha20-Poly1305.
///
/// This is scope-based only: the spend key derives the scope's read key,
/// from which both the X25519 and ML-KEM keys are derived. Any ancestor
/// key holder can independently derive the same keys and decrypt.
pub fn hybrid_encrypt(
    plaintext: &[u8],
    scope: &Scope,
    spend_key: &SpendKeyPair,
    rng: &mut impl CryptoRngCore,
) -> Result<EncryptedEnvelope> {
    // 1. Derive scope's read key from spend key
    let root_read = spend_key.derive_root_read_key();
    let scope_key = if *scope == Scope::root() {
        root_read
    } else {
        root_read.derive_child(scope)?
    };

    // 2. Derive PQ keypair from read key secret + scope
    let read_secret = scope_key.secret_bytes();
    let pq_keypair = derive_pq_keypair(&read_secret, scope);

    // 3. Generate random data key + ephemeral X25519 keypair
    let mut data_key = [0u8; 32];
    rng.fill_bytes(&mut data_key);

    let mut ephemeral_secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret_bytes);
    let ephemeral_static = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_static);

    // 4. Hybrid encapsulate: X25519 ECDH + ML-KEM encapsulation → combined secret
    let recipient = HybridRecipient {
        x25519_public: *scope_key.public_key(),
        mlkem_encapsulation_key: pq_keypair.encapsulation_key().clone(),
        key_id: scope_key.key_id(),
    };
    let encap = hybrid_encapsulate(rng, &recipient, &ephemeral_static);

    // 5. Encrypt payload
    let (ciphertext, nonce, tag) = encrypt_payload(&data_key, plaintext, rng)?;

    // 6. Wrap data key using combined hybrid secret
    let entry = wrap_data_key(
        &data_key,
        &encap.combined_shared_secret,
        &scope_key.key_id(),
        rng,
    )?;

    ephemeral_secret_bytes.zeroize();
    data_key.zeroize();

    // 7. Build envelope
    let mut envelope = EncryptedEnvelope {
        version: EncryptedEnvelope::CURRENT_VERSION,
        algorithm: Algorithm::HybridX25519MlKemChaCha20,
        scope: scope.clone(),
        ephemeral_x25519_public: *ephemeral_public.as_bytes(),
        ephemeral_mlkem_ciphertext: Some(encap.mlkem_ciphertext),
        access_entries: vec![entry],
        nonce,
        ciphertext,
        tag,
        signature: [0u8; 64],
        spend_public_key: *spend_key.verifying_key().as_bytes(),
        access_mode: AccessMode::ScopeBased,
    };

    // 8. Sign
    let signable = envelope.signable_bytes();
    envelope.signature = spend_key.sign_bytes(&signable);

    Ok(envelope)
}

/// Decrypt a hybrid X25519 + ML-KEM-768 envelope.
///
/// The read key can be at the envelope's scope or any ancestor scope;
/// the function will auto-derive to the correct scope.
pub fn hybrid_decrypt(
    envelope: &EncryptedEnvelope,
    read_key: &ReadKeyPair,
    spend_verifying_key: &VerifyingKey,
) -> Result<Vec<u8>> {
    // 1. Verify algorithm
    if envelope.algorithm != Algorithm::HybridX25519MlKemChaCha20 {
        return Err(RokError::DecryptionError(format!(
            "expected hybrid algorithm, got {:?}",
            envelope.algorithm
        )));
    }

    // 2. Verify Ed25519 signature
    let signable = envelope.signable_bytes();
    let signature = Signature::from_bytes(&envelope.signature);
    spend_verifying_key
        .verify(&signable, &signature)
        .map_err(|_| RokError::SignatureVerificationFailed)?;

    // 3. Check scope access and auto-derive if needed
    if !read_key.can_access(&envelope.scope) {
        return Err(RokError::ScopeMismatch {
            key_scope: read_key.scope().to_string(),
            data_scope: envelope.scope.to_string(),
        });
    }

    let derived: Option<ReadKeyPair>;
    let decrypt_key: &ReadKeyPair;
    if read_key.scope() != &envelope.scope {
        derived = Some(read_key.derive_child(&envelope.scope)?);
        decrypt_key = derived.as_ref().unwrap();
    } else {
        derived = None;
        decrypt_key = read_key;
    }

    // 4. Find matching access entry
    let my_key_id = decrypt_key.key_id();
    let entry = envelope
        .access_entries
        .iter()
        .find(|e| e.read_key_id == my_key_id)
        .ok_or_else(|| RokError::NoMatchingAccessEntry(my_key_id.to_string()))?;

    // 5. Derive PQ keypair from (derived) read key secret + envelope scope
    let read_secret = decrypt_key.secret_bytes();
    let pq_keypair = derive_pq_keypair(&read_secret, &envelope.scope);

    // 6. Get ML-KEM ciphertext
    let mlkem_ct = envelope
        .ephemeral_mlkem_ciphertext
        .as_ref()
        .ok_or_else(|| {
            RokError::DecryptionError("hybrid envelope missing ML-KEM ciphertext".into())
        })?;

    // 7. Hybrid decapsulate → combined secret
    let ephemeral_public = X25519PublicKey::from(envelope.ephemeral_x25519_public);
    let combined_secret = hybrid_decapsulate(
        decrypt_key.secret(),
        &ephemeral_public,
        pq_keypair.decapsulation_key(),
        mlkem_ct,
    )?;

    drop(derived);

    // 8. Unwrap data key
    let mut data_key = unwrap_data_key(entry, &combined_secret, &my_key_id)?;

    // 9. Decrypt payload
    let plaintext = decrypt_payload(
        &data_key,
        &envelope.ciphertext,
        &envelope.nonce,
        &envelope.tag,
    )?;

    data_key.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spend() -> SpendKeyPair {
        SpendKeyPair::from_seed(&[42u8; 32])
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_roundtrip() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let mut rng = rand::thread_rng();

        let plaintext = b"Q1 finance report - hybrid encrypted";
        let scope = Scope::new("/finance").unwrap();

        let envelope = hybrid_encrypt(plaintext, &scope, &spend, &mut rng).unwrap();
        assert_eq!(envelope.algorithm, Algorithm::HybridX25519MlKemChaCha20);
        assert_eq!(envelope.access_mode, AccessMode::ScopeBased);
        assert!(envelope.ephemeral_mlkem_ciphertext.is_some());

        // Exact scope key can decrypt
        let decrypted = hybrid_decrypt(&envelope, &finance, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_ancestor_can_decrypt() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let mut rng = rand::thread_rng();

        let scope = Scope::new("/finance/q1").unwrap();
        let plaintext = b"Q1 deep report";

        let envelope = hybrid_encrypt(plaintext, &scope, &spend, &mut rng).unwrap();

        // Root key (ancestor) can decrypt via auto-derivation
        let d1 = hybrid_decrypt(&envelope, &root, &spend.verifying_key()).unwrap();
        assert_eq!(d1, plaintext);

        // /finance key (parent) can decrypt via auto-derivation
        let d2 = hybrid_decrypt(&envelope, &finance, &spend.verifying_key()).unwrap();
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn test_hybrid_sibling_rejected() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let legal = root.derive_child_segment("legal").unwrap();
        let mut rng = rand::thread_rng();

        let scope = Scope::new("/finance").unwrap();
        let envelope = hybrid_encrypt(b"secret", &scope, &spend, &mut rng).unwrap();

        // /legal key cannot decrypt /finance data
        let result = hybrid_decrypt(&envelope, &legal, &spend.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_binary_roundtrip() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let scope = Scope::new("/finance").unwrap();
        let plaintext = b"binary roundtrip test";

        let envelope = hybrid_encrypt(plaintext, &scope, &spend, &mut rng).unwrap();

        // Serialize to binary, deserialize, decrypt
        let bytes = envelope.to_bytes();
        let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();
        let decrypted = hybrid_decrypt(&restored, &root, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_proto_roundtrip() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let scope = Scope::new("/finance").unwrap();
        let plaintext = b"proto roundtrip test";

        let envelope = hybrid_encrypt(plaintext, &scope, &spend, &mut rng).unwrap();

        // Serialize to protobuf, deserialize, decrypt
        let bytes = envelope.to_proto_bytes();
        let restored = EncryptedEnvelope::from_proto_bytes(&bytes).unwrap();
        let decrypted = hybrid_decrypt(&restored, &root, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_tamper_rejected() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let scope = Scope::new("/finance").unwrap();
        let mut envelope = hybrid_encrypt(b"tamper test", &scope, &spend, &mut rng).unwrap();

        // Tamper with ciphertext — signature verification should fail
        envelope.ciphertext[0] ^= 0xff;
        let result = hybrid_decrypt(&envelope, &root, &spend.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_root_scope() {
        let spend = make_spend();
        let root = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let plaintext = b"root scope hybrid";
        let scope = Scope::root();

        let envelope = hybrid_encrypt(plaintext, &scope, &spend, &mut rng).unwrap();
        let decrypted = hybrid_decrypt(&envelope, &root, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
