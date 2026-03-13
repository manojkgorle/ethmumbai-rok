use std::fs;

use rok_core::envelope::EncryptedEnvelope;

use crate::cli::InspectArgs;

pub fn run(args: InspectArgs) -> anyhow::Result<()> {
    let data = fs::read(&args.file)?;
    let envelope = EncryptedEnvelope::from_bytes(&data)?;
    let meta = envelope.metadata();

    println!("=== Envelope: {} ===", args.file.display());
    println!("  Version: {}", meta.version);
    println!("  Algorithm: {:?}", meta.algorithm);
    println!("  Scope: {}", meta.scope);
    println!("  Recipients: {}", meta.recipient_count);
    println!("  Ciphertext size: {} bytes", meta.ciphertext_len);
    println!("  Total file size: {} bytes", data.len());
    println!();
    println!("  Recipient Key IDs:");
    for kid in &meta.recipient_key_ids {
        println!("    - {}", kid);
    }

    if envelope.ephemeral_mlkem_ciphertext.is_some() {
        println!();
        println!("  Hybrid PQ: yes (ML-KEM ciphertext present)");
    }

    Ok(())
}
