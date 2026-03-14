use std::fs;
use std::path::PathBuf;

use rok_core::encoding;
use rok_core::encrypt::{self, Algorithm};
use rok_core::keys::read::ReadKeyPair;
use rok_core::sectioned::SectionedEnvelope;

use crate::cli::{DecryptSectionsArgs, Format};

pub fn run(args: DecryptSectionsArgs) -> anyhow::Result<()> {
    // Parse read key
    let exported = encoding::decode_exported_read_key(&args.key)?;
    let read_key = ReadKeyPair::import(&exported)?;

    // Parse spend public key
    let spend_vk = encoding::decode_spend_public(&args.spend_public)?;

    // Read and deserialize sectioned envelope
    let data = fs::read(&args.file)?;
    let sectioned = match args.format {
        Format::Binary => SectionedEnvelope::from_bytes(&data)?,
        Format::Proto => SectionedEnvelope::from_proto_bytes(&data)?,
    };

    // Output directory
    let output_dir = args.output_dir.unwrap_or_else(|| PathBuf::from("out"));
    fs::create_dir_all(&output_dir)?;

    // Filter sections if requested
    let filter: Option<std::collections::HashSet<&str>> = if args.sections.is_empty() {
        None
    } else {
        Some(args.sections.iter().map(|s| s.as_str()).collect())
    };

    let mut decrypted_count = 0usize;
    let mut skipped_count = 0usize;

    for section in &sectioned.sections {
        if let Some(ref filter) = filter {
            if !filter.contains(section.name.as_str()) {
                continue;
            }
        }

        // Auto-detect algorithm and attempt decrypt
        let result = match section.envelope.algorithm {
            Algorithm::HybridX25519MlKemChaCha20 => {
                rok_pq::envelope::hybrid_decrypt(&section.envelope, &read_key, &spend_vk)
            }
            Algorithm::EciesX25519ChaCha20 => {
                encrypt::decrypt(&section.envelope, &read_key, &spend_vk)
            }
        };

        match result {
            Ok(plaintext) => {
                let out_path = output_dir.join(&section.name);
                fs::write(&out_path, &plaintext)?;
                println!(
                    "  Decrypted: {} -> {} ({} bytes)",
                    section.name,
                    out_path.display(),
                    plaintext.len()
                );
                decrypted_count += 1;
            }
            Err(ref e)
                if e.to_string().contains("scope mismatch")
                    || e.to_string().contains("no matching access entry") =>
            {
                println!("  Skipped: {} (no access)", section.name);
                skipped_count += 1;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    println!();
    println!(
        "Summary: {} decrypted, {} skipped",
        decrypted_count, skipped_count
    );

    Ok(())
}
