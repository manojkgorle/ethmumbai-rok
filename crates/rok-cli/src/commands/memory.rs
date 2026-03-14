use rok_core::encoding;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_sdk::memory::{MemoryReader, MemoryStore, Proposal};
use rok_sdk::storage::fileverse::FileverseBackend;

use crate::cli::{MemoryAction, MemoryArgs};

pub fn run(args: MemoryArgs) -> anyhow::Result<()> {
    if args.api_key.is_empty() {
        anyhow::bail!(
            "Fileverse API key required: set FILEVERSE_API_KEY env var or pass --api-key"
        );
    }

    let backend = FileverseBackend::with_base_url(args.fileverse_url.clone(), args.api_key.clone());

    match args.action {
        MemoryAction::Write(a) => {
            let spend = load_spend_key(&a.spend_seed)?;
            let store = MemoryStore::new(spend, backend);
            let scope = Scope::new(&a.scope)?;

            let content = if let Some(file) = &a.file {
                std::fs::read(file)?
            } else {
                a.data.as_deref().unwrap_or("").as_bytes().to_vec()
            };

            let id = store.write(&scope, &a.key, &content)?;
            println!("Stored memory at {}:{}", a.scope, a.key);
            println!("  Storage ID: {}", id.0);
            Ok(())
        }

        MemoryAction::Read(a) => {
            let spend_vk = encoding::decode_spend_public(&a.spend_public)?;
            let reader = MemoryReader::new(spend_vk, backend);
            let scope = Scope::new(&a.scope)?;
            let read_key = load_read_key(&a.key)?;

            let data = reader.read(&read_key, &scope, &a.name)?;

            if let Some(output_path) = &a.output {
                std::fs::write(output_path, &data)?;
                println!(
                    "Decrypted {}:{} -> {} ({} bytes)",
                    a.scope,
                    a.name,
                    output_path.display(),
                    data.len()
                );
            } else {
                let text = String::from_utf8_lossy(&data);
                println!("{}", text);
            }
            Ok(())
        }

        MemoryAction::List(a) => {
            let spend_vk = encoding::decode_spend_public(&a.spend_public)?;
            let reader = MemoryReader::new(spend_vk, backend);
            let read_key = load_read_key(&a.key)?;

            let memories = reader.list(&read_key)?;
            if memories.is_empty() {
                println!("No memories found at scope {}", read_key.scope());
            } else {
                println!("Memories accessible from scope {}:", read_key.scope());
                for m in &memories {
                    let preview = String::from_utf8_lossy(&m.data);
                    let preview = if preview.len() > 80 {
                        format!("{}...", &preview[..80])
                    } else {
                        preview.to_string()
                    };
                    println!("  [{}] {} = {}", m.scope, m.key, preview);
                }
                println!("\nTotal: {} memories", memories.len());
            }
            Ok(())
        }

        MemoryAction::Grant(a) => {
            let spend = load_spend_key(&a.spend_seed)?;
            let spend_public = encoding::encode_spend_public(&spend.verifying_key());
            let store = MemoryStore::new(spend, backend);
            let scope = Scope::new(&a.scope)?;

            let exported = store.grant_access(&scope)?;
            let encoded = encoding::encode_exported_read_key(&exported);

            println!("=== Granted Memory Access ===");
            println!("  Scope: {}", a.scope);
            println!("  Exported Key: {}", encoded);
            println!("  Spend Public: {}", spend_public);
            println!("\nGive the exported key and spend public to an agent.");
            println!("They can read memories at {} and below.", a.scope);
            Ok(())
        }

        MemoryAction::Propose(a) => {
            let spend = load_spend_key(&a.spend_seed)?;
            let store = MemoryStore::new(spend, backend);
            let scope = Scope::new(&a.scope)?;

            let content = if let Some(file) = &a.file {
                std::fs::read(file)?
            } else {
                a.data.as_deref().unwrap_or("").as_bytes().to_vec()
            };

            let proposal = Proposal {
                scope,
                key: a.key.clone(),
                plaintext: content,
                proposed_by: a.agent_id.clone(),
            };

            let id = store.accept_proposal(&proposal)?;
            println!(
                "Accepted proposal from '{}' at {}:{}",
                a.agent_id, a.scope, a.key
            );
            println!("  Storage ID: {}", id.0);
            Ok(())
        }
    }
}

fn load_spend_key(hex_seed: &str) -> anyhow::Result<SpendKeyPair> {
    let seed_bytes = hex::decode(hex_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    Ok(SpendKeyPair::from_seed(&seed))
}

fn load_read_key(encoded: &str) -> anyhow::Result<ReadKeyPair> {
    let exported = encoding::decode_exported_read_key(encoded)?;
    let key = ReadKeyPair::import(&exported)?;
    Ok(key)
}
