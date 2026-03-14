use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Wire format for encrypted envelopes.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Format {
    /// Custom binary format (ROK\x01 magic header)
    #[default]
    Binary,
    /// Protocol Buffers
    Proto,
}

/// Encryption algorithm choice.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum AlgorithmChoice {
    /// Classical: X25519 ECDH + ChaCha20-Poly1305
    #[default]
    Classical,
    /// Hybrid post-quantum: X25519 + ML-KEM-768 + ChaCha20-Poly1305
    Hybrid,
}

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
    /// Mark a key as revoked in the keyring
    Revoke(RevokeArgs),
    /// Inspect an encrypted envelope's metadata
    Inspect(InspectArgs),
    /// Keyring management: list, export, import, delete
    Keyring(KeyringArgs),
    /// Encrypt multiple sections at different scopes into a single file
    EncryptSections(EncryptSectionsArgs),
    /// Decrypt accessible sections from a sectioned file
    DecryptSections(DecryptSectionsArgs),
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

    /// Wire format for the encrypted envelope
    #[arg(long, value_enum, default_value_t = Format::Binary)]
    pub format: Format,

    /// Use scope-based group encryption (any ancestor key can decrypt)
    #[arg(long, default_value_t = false)]
    pub scope_based: bool,

    /// Encryption algorithm
    #[arg(long, value_enum, default_value_t = AlgorithmChoice::Classical)]
    pub algorithm: AlgorithmChoice,
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

    /// Wire format of the input envelope
    #[arg(long, value_enum, default_value_t = Format::Binary)]
    pub format: Format,
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
pub struct RevokeArgs {
    /// Key ID to revoke (base58-encoded)
    #[arg(long)]
    pub key_id: String,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Scope of the key to revoke (for derivation)
    #[arg(long)]
    pub scope: Option<String>,
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// Encrypted file to inspect (.rok file)
    #[arg(long)]
    pub file: PathBuf,

    /// Wire format of the input envelope
    #[arg(long, value_enum, default_value_t = Format::Binary)]
    pub format: Format,
}

#[derive(clap::Args)]
pub struct KeyringArgs {
    #[command(subcommand)]
    pub action: KeyringAction,
}

#[derive(Subcommand)]
pub enum KeyringAction {
    /// List all keys in the keyring
    List(KeyringListArgs),
    /// Export a read key for delegation
    Export(KeyringExportArgs),
    /// Import a read key from an exported string
    Import(KeyringImportArgs),
    /// Delete a key from the keyring
    Delete(KeyringDeleteArgs),
}

#[derive(clap::Args)]
pub struct KeyringListArgs {
    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Scopes to derive and include (can specify multiple)
    #[arg(long)]
    pub scopes: Vec<String>,
}

#[derive(clap::Args)]
pub struct KeyringExportArgs {
    /// Key ID to export (base58-encoded)
    #[arg(long)]
    pub key_id: String,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Scope of the key (for derivation)
    #[arg(long)]
    pub scope: Option<String>,
}

#[derive(clap::Args)]
pub struct KeyringImportArgs {
    /// Exported read key (base58-encoded)
    #[arg(long)]
    pub exported_key: String,
}

#[derive(clap::Args)]
pub struct KeyringDeleteArgs {
    /// Key ID to delete (base58-encoded)
    #[arg(long)]
    pub key_id: String,

    /// Spend key seed (hex-encoded, needed to populate keyring)
    #[arg(long)]
    pub spend_seed: Option<String>,

    /// Scope of the key (for derivation)
    #[arg(long)]
    pub scope: Option<String>,
}

#[derive(clap::Args)]
pub struct EncryptSectionsArgs {
    /// Section definitions: name:scope:file (repeatable)
    #[arg(long = "section", conflicts_with = "manifest")]
    pub sections: Vec<String>,

    /// JSON manifest file listing sections
    #[arg(long, conflicts_with = "sections")]
    pub manifest: Option<PathBuf>,

    /// Spend key seed (hex-encoded 32 bytes)
    #[arg(long)]
    pub spend_seed: String,

    /// Use scope-based group encryption (default)
    #[arg(long, default_value_t = true)]
    pub scope_based: bool,

    /// Encryption algorithm
    #[arg(long, value_enum, default_value_t = AlgorithmChoice::Classical)]
    pub algorithm: AlgorithmChoice,

    /// Wire format for the output file
    #[arg(long, value_enum, default_value_t = Format::Binary)]
    pub format: Format,

    /// Output file (defaults to output.roks)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct DecryptSectionsArgs {
    /// Sectioned file to decrypt (.roks)
    #[arg(long)]
    pub file: PathBuf,

    /// Exported read key (base58-encoded)
    #[arg(long)]
    pub key: String,

    /// Spend public key (base58-encoded) for signature verification
    #[arg(long)]
    pub spend_public: String,

    /// Output directory (created if needed, files named by section name)
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Wire format of the input file
    #[arg(long, value_enum, default_value_t = Format::Binary)]
    pub format: Format,

    /// Only decrypt specific sections (repeatable; default: all accessible)
    #[arg(long = "section")]
    pub sections: Vec<String>,
}
