use std::fs;

use rok_core::encoding;
use rok_core::encrypt::{self, Algorithm};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::keys::read::ReadKeyPair;

use crate::cli::{DecryptArgs, Format};

pub fn run(args: DecryptArgs) -> anyhow::Result<()> {
    // Parse read key
    let exported = encoding::decode_exported_read_key(&args.key)?;
    let read_key = ReadKeyPair::import(&exported)?;

    // Parse spend public key
    let spend_vk = encoding::decode_spend_public(&args.spend_public)?;

    // Read and deserialize envelope
    let envelope_bytes = fs::read(&args.file)?;
    let envelope = match args.format {
        Format::Binary => EncryptedEnvelope::from_bytes(&envelope_bytes)?,
        Format::Proto => EncryptedEnvelope::from_proto_bytes(&envelope_bytes)?,
    };

    // Decrypt — auto-detect algorithm from envelope
    let plaintext = match envelope.algorithm {
        Algorithm::HybridX25519MlKemChaCha20 => {
            rok_pq::envelope::hybrid_decrypt(&envelope, &read_key, &spend_vk)?
        }
        Algorithm::EciesX25519ChaCha20 => encrypt::decrypt(&envelope, &read_key, &spend_vk)?,
    };

    // Write output
    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.file.clone();
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if let Some(stripped) = name.strip_suffix(".rok") {
            p.set_file_name(stripped);
        } else {
            p.set_file_name(format!("{}.dec", name));
        }
        p
    });

    fs::write(&output_path, &plaintext)?;

    let algo_label = match envelope.algorithm {
        Algorithm::EciesX25519ChaCha20 => "EciesX25519ChaCha20",
        Algorithm::HybridX25519MlKemChaCha20 => "HybridX25519MlKemChaCha20",
    };
    println!(
        "Decrypted {} -> {}",
        args.file.display(),
        output_path.display()
    );
    println!("  Algorithm: {}", algo_label);
    println!("  Scope: {}", envelope.scope);
    println!("  Size: {} bytes", plaintext.len());

    Ok(())
}
