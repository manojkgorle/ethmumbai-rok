use rok_core::encoding;
use rok_core::keys::spend::SpendKeyPair;

use crate::cli::KeygenArgs;

pub fn run(args: KeygenArgs) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::generate(&mut rng);

    let seed_hex = hex::encode(spend.seed());
    let spend_public = encoding::encode_spend_public(&spend.verifying_key());
    let spend_key_id = spend.key_id();

    let root_read = spend.derive_root_read_key();
    let root_read_public = encoding::encode_read_public(root_read.public_key(), root_read.scope());
    let root_read_key_id = root_read.key_id();

    // Export root read key for later use
    let root_exported = encoding::encode_exported_read_key(&root_read.export());

    println!("=== Spend Key (label: {}) ===", args.label);
    println!("  Seed (KEEP SECRET): {}", seed_hex);
    println!("  Public Key: {}", spend_public);
    println!("  Key ID: {}", spend_key_id);
    println!();
    println!("=== Root Read Key (scope: /) ===");
    println!("  Public Key: {}", root_read_public);
    println!("  Key ID: {}", root_read_key_id);
    println!("  Exported (KEEP SECRET): {}", root_exported);

    Ok(())
}
