//! End-to-end integration tests for the rok-core crate.
//!
//! Tests the full flow: keygen -> derive -> encrypt -> serialize -> decrypt,
//! multi-level delegation, and access control enforcement.

use rok_core::encoding;
use rok_core::encrypt::{decrypt, Algorithm, EncryptBuilder, Recipient};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_core::sign;

/// Full lifecycle: keygen -> derive -> encrypt -> serialize -> decrypt
#[test]
fn test_full_lifecycle() {
    let mut rng = rand::thread_rng();

    // 1. Generate spend keypair
    let spend = SpendKeyPair::generate(&mut rng);

    // 2. Derive root and child read keys
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();
    let finance_q1 = finance.derive_child_segment("q1").unwrap();

    // 3. Encrypt data at /finance/q1 for the finance_q1 key
    let plaintext = b"Q1 2025 financial report: revenue $1.2M";
    let recipients = vec![Recipient {
        read_public_key: *finance_q1.public_key(),
        key_id: finance_q1.key_id(),
    }];

    let envelope = EncryptBuilder::new(
        Algorithm::EciesX25519ChaCha20,
        Scope::new("/finance/q1").unwrap(),
    )
    .add_recipients(&recipients)
    .set_spend_key(&spend)
    .encrypt(plaintext, &mut rng)
    .unwrap();

    // 4. Serialize to binary
    let bytes = envelope.to_bytes();
    assert!(bytes.len() > 100); // sanity check

    // 5. Deserialize
    let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(restored.version, envelope.version);
    assert_eq!(restored.algorithm, envelope.algorithm);

    // 6. Decrypt
    let decrypted = decrypt(&restored, &finance_q1, &spend.verifying_key()).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Full lifecycle with protobuf serialization
#[test]
fn test_full_lifecycle_protobuf() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();

    let plaintext = b"protobuf roundtrip test data";
    let recipients = vec![Recipient {
        read_public_key: *root.public_key(),
        key_id: root.key_id(),
    }];

    let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
        .add_recipients(&recipients)
        .set_spend_key(&spend)
        .encrypt(plaintext, &mut rng)
        .unwrap();

    // Serialize to protobuf
    let proto_bytes = envelope.to_proto_bytes();

    // Deserialize from protobuf
    let restored = EncryptedEnvelope::from_proto_bytes(&proto_bytes).unwrap();

    // Decrypt from restored
    let decrypted = decrypt(&restored, &root, &spend.verifying_key()).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Multi-level delegation: root -> finance -> finance/q1
/// Encrypt at /finance/q1, verify access at each level
#[test]
fn test_multi_level_delegation() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();
    let finance_q1 = finance.derive_child_segment("q1").unwrap();
    let legal = root.derive_child_segment("legal").unwrap();

    let plaintext = b"Confidential Q1 data";

    // Encrypt for root, finance, and finance_q1
    let recipients = vec![
        Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        },
        Recipient {
            read_public_key: *finance.public_key(),
            key_id: finance.key_id(),
        },
        Recipient {
            read_public_key: *finance_q1.public_key(),
            key_id: finance_q1.key_id(),
        },
    ];

    let envelope = EncryptBuilder::new(
        Algorithm::EciesX25519ChaCha20,
        Scope::new("/finance/q1").unwrap(),
    )
    .add_recipients(&recipients)
    .set_spend_key(&spend)
    .encrypt(plaintext, &mut rng)
    .unwrap();

    let vk = spend.verifying_key();

    // Root (ancestor of /finance/q1) can decrypt
    assert_eq!(decrypt(&envelope, &root, &vk).unwrap(), plaintext);

    // Finance (ancestor of /finance/q1) can decrypt
    assert_eq!(decrypt(&envelope, &finance, &vk).unwrap(), plaintext);

    // Finance Q1 (exact scope) can decrypt
    assert_eq!(decrypt(&envelope, &finance_q1, &vk).unwrap(), plaintext);

    // Legal (sibling, no access to /finance/q1) cannot decrypt
    assert!(decrypt(&envelope, &legal, &vk).is_err());
}

/// Key export/import roundtrip: derive a key, export, re-import, decrypt
#[test]
fn test_key_export_import_decrypt() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();

    let plaintext = b"delegated access test";
    let recipients = vec![Recipient {
        read_public_key: *finance.public_key(),
        key_id: finance.key_id(),
    }];

    let envelope = EncryptBuilder::new(
        Algorithm::EciesX25519ChaCha20,
        Scope::new("/finance").unwrap(),
    )
    .add_recipients(&recipients)
    .set_spend_key(&spend)
    .encrypt(plaintext, &mut rng)
    .unwrap();

    // Export the finance key
    let exported = finance.export();
    let encoded = encoding::encode_exported_read_key(&exported);

    // Re-import from the encoded string
    let decoded = encoding::decode_exported_read_key(&encoded).unwrap();
    let imported = ReadKeyPair::import(&decoded).unwrap();

    // Imported key should be able to decrypt
    let decrypted = decrypt(&envelope, &imported, &spend.verifying_key()).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Base58 key encoding roundtrip for all key types
#[test]
fn test_key_encoding_roundtrip() {
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();

    // Spend public key
    let spend_enc = encoding::encode_spend_public(&spend.verifying_key());
    let spend_dec = encoding::decode_spend_public(&spend_enc).unwrap();
    assert_eq!(spend.verifying_key(), spend_dec);

    // Read public key
    let read_enc = encoding::encode_read_public(finance.public_key(), finance.scope());
    let (read_dec_key, read_dec_scope) = encoding::decode_read_public(&read_enc).unwrap();
    assert_eq!(&read_dec_key, finance.public_key());
    assert_eq!(read_dec_scope, *finance.scope());

    // Exported read key
    let exported = finance.export();
    let exp_enc = encoding::encode_exported_read_key(&exported);
    let exp_dec = encoding::decode_exported_read_key(&exp_enc).unwrap();
    assert_eq!(exp_dec.secret_bytes, exported.secret_bytes);
    assert_eq!(exp_dec.public_bytes, exported.public_bytes);
    assert_eq!(exp_dec.scope, exported.scope);
}

/// Sign and verify: sign data, serialize, verify
#[test]
fn test_sign_verify_flow() {
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let data = b"important document contents";

    let signature = sign::sign(&spend, data);
    assert!(sign::verify(&spend.verifying_key(), data, &signature).is_ok());

    // Tampered data should fail
    let mut tampered = data.to_vec();
    tampered[0] ^= 0xff;
    assert!(sign::verify(&spend.verifying_key(), &tampered, &signature).is_err());

    // Wrong key should fail
    let other_spend = SpendKeyPair::from_seed(&[99u8; 32]);
    assert!(sign::verify(&other_spend.verifying_key(), data, &signature).is_err());
}

/// Cross-key isolation: encrypt for /finance, verify that /legal cannot access
#[test]
fn test_cross_scope_isolation() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();
    let legal = root.derive_child_segment("legal").unwrap();
    let vk = spend.verifying_key();

    // Encrypt at /finance for finance key only
    let envelope = EncryptBuilder::new(
        Algorithm::EciesX25519ChaCha20,
        Scope::new("/finance").unwrap(),
    )
    .add_recipient(Recipient {
        read_public_key: *finance.public_key(),
        key_id: finance.key_id(),
    })
    .set_spend_key(&spend)
    .encrypt(b"finance only", &mut rng)
    .unwrap();

    // Finance can decrypt
    assert_eq!(decrypt(&envelope, &finance, &vk).unwrap(), b"finance only");

    // Legal cannot (scope mismatch)
    let err = decrypt(&envelope, &legal, &vk).unwrap_err();
    assert!(err.to_string().contains("scope mismatch"));

    // Root can (ancestor scope, but no access entry for root key)
    // Root has scope access but wasn't added as recipient
    let err = decrypt(&envelope, &root, &vk).unwrap_err();
    assert!(err.to_string().contains("no matching access entry"));
}

/// Deterministic derivation: same seed always produces same key hierarchy
#[test]
fn test_deterministic_derivation() {
    let spend1 = SpendKeyPair::from_seed(&[42u8; 32]);
    let spend2 = SpendKeyPair::from_seed(&[42u8; 32]);

    let root1 = spend1.derive_root_read_key();
    let root2 = spend2.derive_root_read_key();
    assert_eq!(root1.key_id(), root2.key_id());
    assert_eq!(root1.public_key(), root2.public_key());

    let fin1 = root1.derive_child_segment("finance").unwrap();
    let fin2 = root2.derive_child_segment("finance").unwrap();
    assert_eq!(fin1.key_id(), fin2.key_id());

    let q1_direct = root1
        .derive_child(&Scope::new("/finance/q1").unwrap())
        .unwrap();
    let q1_step = fin1.derive_child_segment("q1").unwrap();
    assert_eq!(q1_direct.key_id(), q1_step.key_id());
}

/// Envelope binary serialization preserves all fields through roundtrip
#[test]
fn test_binary_serialization_preserves_all_fields() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();
    let finance = root.derive_child_segment("finance").unwrap();

    let recipients = vec![
        Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        },
        Recipient {
            read_public_key: *finance.public_key(),
            key_id: finance.key_id(),
        },
    ];

    let envelope = EncryptBuilder::new(
        Algorithm::EciesX25519ChaCha20,
        Scope::new("/finance").unwrap(),
    )
    .add_recipients(&recipients)
    .set_spend_key(&spend)
    .encrypt(b"test data for serialization", &mut rng)
    .unwrap();

    // Binary roundtrip
    let bytes = envelope.to_bytes();
    let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();

    assert_eq!(restored.version, envelope.version);
    assert_eq!(restored.algorithm, envelope.algorithm);
    assert_eq!(restored.scope, envelope.scope);
    assert_eq!(
        restored.ephemeral_x25519_public,
        envelope.ephemeral_x25519_public
    );
    assert_eq!(
        restored.ephemeral_mlkem_ciphertext,
        envelope.ephemeral_mlkem_ciphertext
    );
    assert_eq!(restored.access_entries.len(), 2);
    assert_eq!(restored.nonce, envelope.nonce);
    assert_eq!(restored.ciphertext, envelope.ciphertext);
    assert_eq!(restored.tag, envelope.tag);
    assert_eq!(restored.signature, envelope.signature);
    assert_eq!(restored.spend_public_key, envelope.spend_public_key);

    // Both recipients can still decrypt from restored envelope
    let vk = spend.verifying_key();
    assert_eq!(
        decrypt(&restored, &root, &vk).unwrap(),
        b"test data for serialization"
    );
    assert_eq!(
        decrypt(&restored, &finance, &vk).unwrap(),
        b"test data for serialization"
    );
}

/// Tampered envelope is rejected at signature verification
#[test]
fn test_tampered_envelope_rejected() {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root = spend.derive_root_read_key();

    let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
        .add_recipient(Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        })
        .set_spend_key(&spend)
        .encrypt(b"important data", &mut rng)
        .unwrap();

    // Serialize, tamper, deserialize
    let mut bytes = envelope.to_bytes();
    // Tamper with a byte in the ciphertext area (after the header)
    let tamper_pos = bytes.len() / 2;
    bytes[tamper_pos] ^= 0xff;

    // Deserialization itself might succeed (it's just bytes)
    // But decryption should fail (signature won't match)
    if let Ok(tampered) = EncryptedEnvelope::from_bytes(&bytes) {
        let result = decrypt(&tampered, &root, &spend.verifying_key());
        assert!(result.is_err(), "tampered envelope should fail decryption");
    }
    // If from_bytes fails, that's also acceptable — corruption detected early
}
