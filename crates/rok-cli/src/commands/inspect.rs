use std::fs;

use rok_core::envelope::EncryptedEnvelope;
use rok_core::sectioned::{SectionedEnvelope, SECTIONED_MAGIC};

use crate::cli::{Format, InspectArgs};

pub fn run(args: InspectArgs) -> anyhow::Result<()> {
    let data = fs::read(&args.file)?;

    // Auto-detect sectioned format
    match args.format {
        Format::Binary => {
            if data.len() >= 4 && &data[..4] == SECTIONED_MAGIC {
                return inspect_sectioned(SectionedEnvelope::from_bytes(&data)?, &args, &data);
            }
        }
        Format::Proto => {
            // Try sectioned first, fall back to single envelope
            if let Ok(sectioned) = SectionedEnvelope::from_proto_bytes(&data) {
                if !sectioned.sections.is_empty() {
                    return inspect_sectioned(sectioned, &args, &data);
                }
            }
        }
    }

    // Single envelope path
    let envelope = match args.format {
        Format::Binary => EncryptedEnvelope::from_bytes(&data)?,
        Format::Proto => EncryptedEnvelope::from_proto_bytes(&data)?,
    };
    inspect_single(&envelope, &args, &data)
}

fn inspect_single(
    envelope: &EncryptedEnvelope,
    args: &InspectArgs,
    data: &[u8],
) -> anyhow::Result<()> {
    let meta = envelope.metadata();

    let format_label = match args.format {
        Format::Binary => "binary",
        Format::Proto => "protobuf",
    };
    println!("=== Envelope: {} ===", args.file.display());
    println!("  Version: {}", meta.version);
    println!("  Algorithm: {:?}", meta.algorithm);
    let mode_label = match meta.access_mode {
        rok_core::encrypt::AccessMode::Recipient => "per-recipient",
        rok_core::encrypt::AccessMode::ScopeBased => "scope-based",
    };
    println!("  Access mode: {}", mode_label);
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

    if let Some(ref mlkem_ct) = envelope.ephemeral_mlkem_ciphertext {
        println!();
        println!("  Hybrid PQ: yes");
        println!("  ML-KEM ciphertext size: {} bytes", mlkem_ct.len());
    }

    Ok(())
}

fn inspect_sectioned(
    sectioned: SectionedEnvelope,
    args: &InspectArgs,
    data: &[u8],
) -> anyhow::Result<()> {
    let meta = sectioned.metadata();
    let format_label = match args.format {
        Format::Binary => "binary",
        Format::Proto => "protobuf",
    };

    println!("=== Sectioned Envelope: {} ===", args.file.display());
    println!("  Version: {}", meta.version);
    println!("  Sections: {}", meta.section_count);
    println!("  Format: {}", format_label);
    println!("  Total file size: {} bytes", data.len());
    println!();

    for (i, section) in meta.sections.iter().enumerate() {
        let mode_label = match section.access_mode {
            rok_core::encrypt::AccessMode::Recipient => "per-recipient",
            rok_core::encrypt::AccessMode::ScopeBased => "scope-based",
        };
        println!("  Section {} - \"{}\":", i + 1, section.name);
        println!("    Scope: {}", section.scope);
        println!("    Algorithm: {:?}", section.algorithm);
        println!("    Access mode: {}", mode_label);
        println!("    Recipients: {}", section.recipient_count);
        println!("    Ciphertext size: {} bytes", section.ciphertext_len);
    }

    Ok(())
}
