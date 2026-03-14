use std::fs;

use rok_core::encoding;
use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient};
use rok_core::keys::key_id::KeyId;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

use crate::cli::{AlgorithmChoice, EncryptArgs, Format};

pub fn run(args: EncryptArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);
    let scope = Scope::new(&args.scope)?;

    // Read input file
    let plaintext = fs::read(&args.file)?;
    let mut rng = rand::thread_rng();

    let envelope = match args.algorithm {
        AlgorithmChoice::Hybrid => {
            // Hybrid mode: scope-based only
            if !args.scope_based {
                anyhow::bail!("hybrid algorithm requires --scope-based");
            }
            if !args.recipient.is_empty() {
                anyhow::bail!("hybrid algorithm does not support --recipient (scope-based only)");
            }
            rok_pq::envelope::hybrid_encrypt(&plaintext, &scope, &spend, &mut rng)?
        }
        AlgorithmChoice::Classical => {
            let mut builder = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope);
            builder.set_spend_key(&spend);

            if args.scope_based {
                builder.set_scope_based();
            } else {
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
                    anyhow::bail!(
                        "at least one --recipient is required, or use --scope-based"
                    );
                }
                builder.add_recipients(&recipients);
            }

            builder.encrypt(&plaintext, &mut rng)?
        }
    };

    // Serialize
    let envelope_bytes = match args.format {
        Format::Binary => envelope.to_bytes(),
        Format::Proto => envelope.to_proto_bytes(),
    };

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

    fs::write(&output_path, &envelope_bytes)?;

    let format_label = match args.format {
        Format::Binary => "binary",
        Format::Proto => "protobuf",
    };
    let mode_label = match envelope.access_mode {
        rok_core::encrypt::AccessMode::Recipient => "per-recipient",
        rok_core::encrypt::AccessMode::ScopeBased => "scope-based",
    };
    let algo_label = match envelope.algorithm {
        Algorithm::EciesX25519ChaCha20 => "EciesX25519ChaCha20",
        Algorithm::HybridX25519MlKemChaCha20 => "HybridX25519MlKemChaCha20",
    };
    println!(
        "Encrypted {} -> {}",
        args.file.display(),
        output_path.display()
    );
    println!("  Algorithm: {}", algo_label);
    println!("  Scope: {}", envelope.scope);
    println!("  Access mode: {}", mode_label);
    println!("  Recipients: {}", envelope.access_entries.len());
    println!("  Format: {}", format_label);
    println!("  Size: {} bytes", envelope_bytes.len());

    Ok(())
}
