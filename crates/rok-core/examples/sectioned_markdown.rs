//! Sectioned Markdown Encryption Example
//!
//! Demonstrates encrypting a markdown document where different sections
//! have different scope-based access controls. Only key holders with
//! the matching (or ancestor) scope can decrypt each section.
//!
//! Keys derived *after* encryption still work because scope-based
//! derivation is deterministic (HKDF-SHA256).
//!
//! Run with:
//!   cargo run --example sectioned_markdown -p rok-core

use rok_core::encrypt::{decrypt, Algorithm, EncryptBuilder};
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_core::sectioned::SectionedEnvelopeBuilder;

/// A parsed markdown section with a scope tag.
struct MarkdownSection {
    name: String,
    scope: String,
    content: String,
}

/// Parse a markdown document into scope-tagged sections.
///
/// Expected format — each section starts with a heading containing a scope annotation:
/// ```markdown
/// # Section Name <!-- scope: /path -->
/// body text...
/// ```
///
/// Any text before the first heading goes into an "intro" section at root scope.
fn parse_markdown(input: &str) -> Vec<MarkdownSection> {
    let mut sections = Vec::new();
    let mut current_name = String::from("intro");
    let mut current_scope = String::from("/");
    let mut current_body = String::new();

    for line in input.lines() {
        if line.starts_with('#') {
            // Flush previous section
            let body = current_body.trim().to_string();
            if !body.is_empty() {
                sections.push(MarkdownSection {
                    name: current_name.clone(),
                    scope: current_scope.clone(),
                    content: body,
                });
            }
            current_body.clear();

            // Parse heading: "# Title <!-- scope: /path -->"
            if let Some(scope_start) = line.find("<!-- scope:") {
                let after = &line[scope_start + 11..];
                if let Some(scope_end) = after.find("-->") {
                    current_scope = after[..scope_end].trim().to_string();
                }
                current_name = line[..scope_start].trim_start_matches('#').trim().to_string();
            } else {
                current_name = line.trim_start_matches('#').trim().to_string();
                current_scope = "/".to_string();
            }
        } else {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }

    // Flush last section
    let body = current_body.trim().to_string();
    if !body.is_empty() {
        sections.push(MarkdownSection {
            name: current_name,
            scope: current_scope,
            content: body,
        });
    }

    sections
}

fn main() {
    let document = r#"# Company Report <!-- scope: / -->
This is the public introduction visible to all key holders.

## Finance Summary <!-- scope: /finance -->
Revenue: $4.2M this quarter.
Burn rate is decreasing. Runway extended to 18 months.

## Finance Detailed <!-- scope: /finance/detailed -->
Account breakdown:
- AWS costs: $120k/mo
- Payroll: $890k/mo
- Revenue by client: [REDACTED in summary]

## Legal <!-- scope: /legal -->
Pending litigation: 2 cases.
IP portfolio: 12 patents filed, 4 granted.

## Engineering <!-- scope: /engineering -->
Sprint velocity: 42 points/week.
Next milestone: v2.0 launch in Q3.
"#;

    // --- Step 1: Parse the markdown ---
    let sections = parse_markdown(document);
    println!("Parsed {} sections from markdown:\n", sections.len());
    for s in &sections {
        println!("  [{}] scope={} ({} bytes)", s.name, s.scope, s.content.len());
    }

    // --- Step 2: Encrypt each section with its scope ---
    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);

    let mut builder = SectionedEnvelopeBuilder::new();
    for s in &sections {
        let scope = Scope::new(&s.scope).unwrap();
        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope)
            .set_spend_key(&spend)
            .set_scope_based()
            .encrypt(s.content.as_bytes(), &mut rng)
            .unwrap();
        builder.add_section(s.name.clone(), envelope).unwrap();
    }
    let sectioned = builder.build().unwrap();

    let bytes = sectioned.to_bytes();
    println!("\nEncrypted sectioned envelope: {} bytes total", bytes.len());

    // --- Step 3: Derive keys for different roles ---
    let root_read = spend.derive_root_read_key();
    let finance_key = root_read.derive_child_segment("finance").unwrap();
    let legal_key = root_read.derive_child_segment("legal").unwrap();
    let engineering_key = root_read.derive_child_segment("engineering").unwrap();

    // Derive a /finance/detailed key BEFORE encryption exists
    let pre_finance_detailed = finance_key
        .derive_child_segment("detailed")
        .unwrap();
    println!(
        "\nPre-encryption /finance/detailed key:  key_id={}",
        pre_finance_detailed.key_id()
    );

    // --- Step 4: Try decrypting with different keys ---
    println!("\n--- Decrypt with ROOT key (has access to everything) ---");
    decrypt_sections(&sectioned, &root_read, &spend);

    println!("\n--- Decrypt with FINANCE key (scope: /finance) ---");
    decrypt_sections(&sectioned, &finance_key, &spend);

    println!("\n--- Decrypt with LEGAL key (scope: /legal) ---");
    decrypt_sections(&sectioned, &legal_key, &spend);

    println!("\n--- Decrypt with ENGINEERING key (scope: /engineering) ---");
    decrypt_sections(&sectioned, &engineering_key, &spend);

    println!("\n--- Decrypt with PRE-ENCRYPTION /finance/detailed key ---");
    decrypt_sections(&sectioned, &pre_finance_detailed, &spend);

    // --- Step 5: Derive the SAME key AFTER encryption, compare ---
    println!("\n--- Post-encryption key derivation ---");
    let post_spend = SpendKeyPair::from_seed(&[42u8; 32]); // same seed = same keys
    let post_root = post_spend.derive_root_read_key();
    let post_finance_detailed = post_root
        .derive_child_segment("finance")
        .unwrap()
        .derive_child_segment("detailed")
        .unwrap();
    println!(
        "Post-encryption /finance/detailed key: key_id={}",
        post_finance_detailed.key_id()
    );
    println!(
        "Keys match: {} (deterministic HKDF derivation)",
        pre_finance_detailed.key_id() == post_finance_detailed.key_id()
    );

    println!("\n--- Decrypt with POST-ENCRYPTION /finance/detailed key ---");
    decrypt_sections(&sectioned, &post_finance_detailed, &post_spend);
}

fn decrypt_sections(
    sectioned: &rok_core::sectioned::SectionedEnvelope,
    key: &rok_core::keys::read::ReadKeyPair,
    spend: &SpendKeyPair,
) {
    let spend_vk = spend.verifying_key();
    for section in &sectioned.sections {
        match decrypt(&section.envelope, key, &spend_vk) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                let preview = if text.len() > 80 {
                    format!("{}...", &text[..80])
                } else {
                    text.to_string()
                };
                println!("  [{}] OK: {}", section.name, preview);
            }
            Err(e) => {
                println!("  [{}] DENIED: {}", section.name, e);
            }
        }
    }
}
