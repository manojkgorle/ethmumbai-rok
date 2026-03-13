use std::fs;

use rok_core::envelope::EncryptedEnvelope;

use crate::cli::{Format, InspectArgs};

pub fn run(args: InspectArgs) -> anyhow::Result<()> {
    let data = fs::read(&args.file)?;
    let envelope = match args.format {
        Format::Binary => EncryptedEnvelope::from_bytes(&data)?,
        Format::Proto => EncryptedEnvelope::from_proto_bytes(&data)?,
    };
    let meta = envelope.metadata();

    let format_label = match args.format {
        Format::Binary => "binary",
        Format::Proto => "protobuf",
    };
    println!("=== Envelope: {} ===", args.file.display());
    println!("  Version: {}", meta.version);
    println!("  Algorithm: {:?}", meta.algorithm);
    println!("  Scope: {}", meta.scope);
    println!("  Format: {}", format_label);
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
