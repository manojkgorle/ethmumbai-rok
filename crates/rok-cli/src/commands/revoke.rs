use rok_core::keyring::KeyStore;
use rok_core::keys::key_id::KeyId;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_sdk::keyring::MemoryKeyring;

use crate::cli::RevokeArgs;

pub fn run(args: RevokeArgs) -> anyhow::Result<()> {
    // Parse the key_id from base58
    let key_id = KeyId::from_base58(&args.key_id)?;

    // Build an in-memory keyring with the derived key so we can demonstrate revocation.
    // In a real implementation, this would load from a persistent keyring file.
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let root = spend.derive_root_read_key();

    let mut keyring = MemoryKeyring::new();

    // Store the root key
    keyring.store_read_key(&root)?;

    // If a scope is given, derive and store that key too
    if let Some(ref scope_str) = args.scope {
        let scope = Scope::new(scope_str)?;
        let derived = root.derive_child(&scope)?;
        keyring.store_read_key(&derived)?;
    }

    // Revoke the specified key
    match keyring.revoke_key(&key_id) {
        Ok(()) => {
            println!("Key revoked: {}", key_id);
            println!();
            println!("Note: This is an advisory revocation (local keyring mark).");
            println!("For true revocation, re-encrypt affected data with `rok encrypt`");
            println!("excluding the revoked key from the recipient list.");
        }
        Err(e) => {
            anyhow::bail!("Failed to revoke key: {}", e);
        }
    }

    Ok(())
}
