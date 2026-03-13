use std::fs;

use rok_core::encoding;
use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient};
use rok_core::keys::key_id::KeyId;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

use crate::cli::EncryptArgs;

pub fn run(args: EncryptArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let scope = Scope::new(&args.scope)?;

    // Parse recipients
    let mut recipients = Vec::new();
    for encoded in &args.recipient {
        let (public_key, _scope) = encoding::decode_read_public(encoded)?;
        let key_id = KeyId::from_public_bytes(public_key.as_bytes());
        recipients.push(Recipient {
            read_public_key: public_key,
            key_id,
        });
    }

    if recipients.is_empty() {
        anyhow::bail!("at least one --recipient is required");
    }

    // Read input file
    let plaintext = fs::read(&args.file)?;

    // Encrypt
    let mut rng = rand::thread_rng();
    let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope)
        .add_recipients(&recipients)
        .set_spend_key(&spend)
        .encrypt(&plaintext, &mut rng)?;

    // Write output
    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.file.clone();
        let new_name = format!(
            "{}.rok",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    let envelope_bytes = envelope.to_bytes();
    fs::write(&output_path, &envelope_bytes)?;

    println!("Encrypted {} -> {}", args.file.display(), output_path.display());
    println!("  Scope: {}", envelope.scope);
    println!("  Recipients: {}", envelope.access_entries.len());
    println!("  Size: {} bytes", envelope_bytes.len());

    Ok(())
}
