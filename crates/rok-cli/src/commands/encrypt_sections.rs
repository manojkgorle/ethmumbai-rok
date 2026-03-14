use std::fs;
use std::path::PathBuf;

use rok_core::encrypt::{Algorithm, EncryptBuilder};
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_core::sectioned::SectionedEnvelopeBuilder;

use crate::cli::{AlgorithmChoice, EncryptSectionsArgs, Format};

/// A parsed section definition.
struct SectionDef {
    name: String,
    scope: String,
    file: PathBuf,
}

pub fn run(args: EncryptSectionsArgs) -> anyhow::Result<()> {
    // Parse spend seed
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let spend = SpendKeyPair::from_seed(&seed);

    // Parse section definitions
    let section_defs = if let Some(manifest_path) = &args.manifest {
        parse_manifest(manifest_path)?
    } else if !args.sections.is_empty() {
        parse_section_flags(&args.sections)?
    } else {
        anyhow::bail!("provide --section flags or --manifest");
    };

    if section_defs.is_empty() {
        anyhow::bail!("at least one section is required");
    }

    let mut rng = rand::thread_rng();
    let mut builder = SectionedEnvelopeBuilder::new();

    for def in &section_defs {
        let plaintext = fs::read(&def.file)?;
        let scope = Scope::new(&def.scope)?;

        let envelope = match args.algorithm {
            AlgorithmChoice::Hybrid => {
                rok_pq::envelope::hybrid_encrypt(&plaintext, &scope, &spend, &mut rng)?
            }
            AlgorithmChoice::Classical => {
                let mut eb = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope);
                eb.set_spend_key(&spend);
                if args.scope_based {
                    eb.set_scope_based();
                }
                eb.encrypt(&plaintext, &mut rng)?
            }
        };

        builder.add_section(def.name.clone(), envelope)?;
    }

    let sectioned = builder.build()?;

    // Serialize
    let bytes = match args.format {
        Format::Binary => sectioned.to_bytes(),
        Format::Proto => sectioned.to_proto_bytes(),
    };

    let output_path = args.output.unwrap_or_else(|| PathBuf::from("output.roks"));
    fs::write(&output_path, &bytes)?;

    // Print summary
    let format_label = match args.format {
        Format::Binary => "binary",
        Format::Proto => "protobuf",
    };
    let algo_label = match args.algorithm {
        AlgorithmChoice::Classical => "classical",
        AlgorithmChoice::Hybrid => "hybrid",
    };
    println!(
        "Encrypted {} sections -> {}",
        section_defs.len(),
        output_path.display()
    );
    for def in &section_defs {
        println!("  - {} (scope: {})", def.name, def.scope);
    }
    println!("  Algorithm: {}", algo_label);
    println!("  Format: {}", format_label);
    println!("  Total size: {} bytes", bytes.len());

    Ok(())
}

fn parse_section_flags(flags: &[String]) -> anyhow::Result<Vec<SectionDef>> {
    let mut defs = Vec::new();
    for flag in flags {
        let parts: Vec<&str> = flag.splitn(3, ':').collect();
        if parts.len() != 3 {
            anyhow::bail!(
                "invalid --section format '{}': expected name:scope:file",
                flag
            );
        }
        defs.push(SectionDef {
            name: parts[0].to_string(),
            scope: parts[1].to_string(),
            file: PathBuf::from(parts[2]),
        });
    }
    Ok(defs)
}

fn parse_manifest(path: &PathBuf) -> anyhow::Result<Vec<SectionDef>> {
    let data = fs::read_to_string(path)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    let mut defs = Vec::new();
    for entry in entries {
        let name = entry["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest entry missing 'name'"))?
            .to_string();
        let scope = entry["scope"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest entry missing 'scope'"))?
            .to_string();
        let file = entry["file"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest entry missing 'file'"))?;
        defs.push(SectionDef {
            name,
            scope,
            file: PathBuf::from(file),
        });
    }
    Ok(defs)
}
