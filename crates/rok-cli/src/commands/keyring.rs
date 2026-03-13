use rok_core::encoding;
use rok_core::keyring::KeyStore;
use rok_core::keys::key_id::KeyId;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_sdk::keyring::MemoryKeyring;

use crate::cli::KeyringArgs;

pub fn run(args: KeyringArgs) -> anyhow::Result<()> {
    match args.action {
        crate::cli::KeyringAction::List(list_args) => run_list(list_args),
        crate::cli::KeyringAction::Export(export_args) => run_export(export_args),
        crate::cli::KeyringAction::Import(import_args) => run_import(import_args),
        crate::cli::KeyringAction::Delete(delete_args) => run_delete(delete_args),
    }
}

fn run_list(args: crate::cli::KeyringListArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let root = spend.derive_root_read_key();

    let mut keyring = MemoryKeyring::new();
    keyring.store_spend_key("default", &spend)?;
    keyring.store_read_key(&root)?;

    // Derive and store keys for common scopes if provided
    for scope_str in &args.scopes {
        let scope = Scope::new(scope_str)?;
        let derived = root.derive_child(&scope)?;
        keyring.store_read_key(&derived)?;
    }

    println!("=== Keyring ===");
    println!();
    println!("Spend Keys:");
    println!("  - label: default, key_id: {}", spend.key_id());
    println!();

    let read_keys = keyring.list_read_keys()?;
    println!("Read Keys ({}):", read_keys.len());
    for info in &read_keys {
        let status = if info.revoked { " [REVOKED]" } else { "" };
        let parent = info
            .parent_key_id
            .map(|p| format!(" (parent: {})", p))
            .unwrap_or_default();
        println!(
            "  - key_id: {}, scope: {}{}{}",
            info.key_id, info.scope, parent, status
        );
    }

    Ok(())
}

fn run_export(args: crate::cli::KeyringExportArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let root = spend.derive_root_read_key();

    // Find the key to export
    let key_id = KeyId::from_base58(&args.key_id)?;

    // Check if it's the root key
    let key_to_export = if root.key_id() == key_id {
        root
    } else {
        // Try to derive by scope if provided
        if let Some(ref scope_str) = args.scope {
            let scope = Scope::new(scope_str)?;
            let derived = root.derive_child(&scope)?;
            if derived.key_id() != key_id {
                anyhow::bail!(
                    "derived key at scope {} has key_id {}, not {}",
                    scope_str,
                    derived.key_id(),
                    key_id
                );
            }
            derived
        } else {
            anyhow::bail!(
                "key_id {} not found. Provide --scope to derive the matching key.",
                key_id
            );
        }
    };

    let exported = encoding::encode_exported_read_key(&key_to_export.export());
    let public = encoding::encode_read_public(key_to_export.public_key(), key_to_export.scope());

    println!("=== Exported Read Key ===");
    println!("  Key ID: {}", key_to_export.key_id());
    println!("  Scope: {}", key_to_export.scope());
    println!("  Public Key: {}", public);
    println!("  Exported Key (KEEP SECRET): {}", exported);

    Ok(())
}

fn run_import(args: crate::cli::KeyringImportArgs) -> anyhow::Result<()> {
    let exported = encoding::decode_exported_read_key(&args.exported_key)?;
    let imported = ReadKeyPair::import(&exported)?;

    let mut keyring = MemoryKeyring::new();
    keyring.store_read_key(&imported)?;

    println!("Imported read key:");
    println!("  Key ID: {}", imported.key_id());
    println!("  Scope: {}", imported.scope());
    if let Some(parent) = imported.parent_key_id() {
        println!("  Parent Key ID: {}", parent);
    }

    Ok(())
}

fn run_delete(args: crate::cli::KeyringDeleteArgs) -> anyhow::Result<()> {
    let key_id = KeyId::from_base58(&args.key_id)?;

    // In a real implementation, this would load from a persistent keyring file.
    // For demonstration, we create a keyring and show the operation.
    let mut keyring = MemoryKeyring::new();

    // We need the key to exist to delete it. With a persistent keyring this
    // would just load and delete. For now, if a spend_seed is given, populate.
    if let Some(ref spend_seed) = args.spend_seed {
        let seed_bytes = hex::decode(spend_seed)?;
        if seed_bytes.len() != 32 {
            anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let spend = SpendKeyPair::from_seed(&seed);
        let root = spend.derive_root_read_key();
        keyring.store_read_key(&root)?;

        if let Some(ref scope_str) = args.scope {
            let scope = Scope::new(scope_str)?;
            let derived = root.derive_child(&scope)?;
            keyring.store_read_key(&derived)?;
        }
    }

    match keyring.delete_key(&key_id) {
        Ok(()) => println!("Deleted key: {}", key_id),
        Err(e) => anyhow::bail!("Failed to delete key: {}", e),
    }

    Ok(())
}
