use std::fs;

use rok_core::encoding;
use rok_core::sign;

use crate::cli::VerifyArgs;

pub fn run(args: VerifyArgs) -> anyhow::Result<()> {
    let spend_vk = encoding::decode_spend_public(&args.spend_public)?;

    let data = fs::read(&args.file)?;
    let sig_bytes = fs::read(&args.sig)?;

    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "signature must be exactly 64 bytes, got {}",
            sig_bytes.len()
        );
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);

    match sign::verify(&spend_vk, &data, &signature) {
        Ok(()) => {
            println!("Signature VALID");
            println!("  File: {}", args.file.display());
            println!("  Signature: {}", args.sig.display());
            Ok(())
        }
        Err(e) => {
            println!("Signature INVALID: {}", e);
            std::process::exit(1);
        }
    }
}
