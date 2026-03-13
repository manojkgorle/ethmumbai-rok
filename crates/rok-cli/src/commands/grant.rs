use rok_core::encoding;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

use crate::cli::GrantArgs;

pub fn run(args: GrantArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let root = spend.derive_root_read_key();
    let scope = Scope::new(&args.scope)?;
    let derived = root.derive_child(&scope)?;

    let public = encoding::encode_read_public(derived.public_key(), derived.scope());
    let exported = encoding::encode_exported_read_key(&derived.export());

    println!("=== Granted Read Key ===");
    println!("  Scope: {}", args.scope);
    println!("  Key ID: {}", derived.key_id());
    println!("  Public Key (share with encryptors): {}", public);
    println!("  Exported Key (share with recipient): {}", exported);

    Ok(())
}
