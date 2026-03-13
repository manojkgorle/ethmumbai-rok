use std::fs;

use rok_core::keys::spend::SpendKeyPair;
use rok_core::sign;

use crate::cli::SignArgs;

pub fn run(args: SignArgs) -> anyhow::Result<()> {
    let seed_bytes = hex::decode(&args.spend_seed)?;
    if seed_bytes.len() != 32 {
        anyhow::bail!("spend seed must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let spend = SpendKeyPair::from_seed(&seed);

    let data = fs::read(&args.file)?;
    let signature = sign::sign(&spend, &data);

    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.file.clone();
        let new_name = format!(
            "{}.sig",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    fs::write(&output_path, signature)?;

    println!(
        "Signed {} -> {}",
        args.file.display(),
        output_path.display()
    );
    println!("  Signature: {}", hex::encode(signature));

    Ok(())
}
