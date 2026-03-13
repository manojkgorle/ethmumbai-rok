use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rok", about = "Read-Only Keys cryptography toolkit")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate a new spend keypair and root read key
    Keygen(KeygenArgs),
    /// Derive a child read key from a parent
    Derive(DeriveArgs),
    /// Encrypt a file for a scope
    Encrypt(EncryptArgs),
    /// Decrypt a file with a read key
    Decrypt(DecryptArgs),
    /// Sign a file with spend key
    Sign(SignArgs),
    /// Verify a file signature
    Verify(VerifyArgs),
    /// Export a derived read key for delegation
    Grant(GrantArgs),
    /// Inspect an encrypted envelope's metadata
    Inspect(InspectArgs),
}

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Label for the spend key (for identification)
    #[arg(long, default_value = "default")]
    pub label: String,
}

#[derive(clap::Args)]
pub struct DeriveArgs {
    /// Scope path for the derived key (e.g., /finance/q1)
    #[arg(long)]
    pub scope: String,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,
}

#[derive(clap::Args)]
pub struct EncryptArgs {
    /// File to encrypt
    #[arg(long)]
    pub file: PathBuf,

    /// Scope for the encrypted data
    #[arg(long)]
    pub scope: String,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Recipient read public keys (base58-encoded, can specify multiple)
    #[arg(long)]
    pub recipient: Vec<String>,

    /// Output file (defaults to <file>.rok)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct DecryptArgs {
    /// File to decrypt (.rok file)
    #[arg(long)]
    pub file: PathBuf,

    /// Exported read key (base58-encoded)
    #[arg(long)]
    pub key: String,

    /// Spend public key (base58-encoded) for signature verification
    #[arg(long)]
    pub spend_public: String,

    /// Output file (defaults to stripping .rok extension)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct SignArgs {
    /// File to sign
    #[arg(long)]
    pub file: PathBuf,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Output signature file (defaults to <file>.sig)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// File to verify
    #[arg(long)]
    pub file: PathBuf,

    /// Signature file
    #[arg(long)]
    pub sig: PathBuf,

    /// Spend public key (base58-encoded)
    #[arg(long)]
    pub spend_public: String,
}

#[derive(clap::Args)]
pub struct GrantArgs {
    /// Scope for the derived read key
    #[arg(long)]
    pub scope: String,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// Encrypted file to inspect (.rok file)
    #[arg(long)]
    pub file: PathBuf,
}
