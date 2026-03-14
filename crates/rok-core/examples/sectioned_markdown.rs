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

use rok_core::encrypt::{decrypt, Algorithm, EncryptBuilder, Recipient};
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_core::sectioned::SectionedEnvelopeBuilder;

/// A parsed markdown section with one or more scope tags.
struct MarkdownSection {
    name: String,
    scopes: Vec<String>,
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
/// Multiple scopes (cross-scope access) use comma separation:
/// ```markdown
/// ## Joint Review <!-- scope: /finance, /legal -->
/// ```
///
/// Any text before the first heading goes into an "intro" section at root scope.
fn parse_markdown(input: &str) -> Vec<MarkdownSection> {
    let mut sections = Vec::new();
    let mut current_name = String::from("intro");
    let mut current_scopes = vec!["/".to_string()];
    let mut current_body = String::new();

    for line in input.lines() {
        if line.starts_with('#') {
            // Flush previous section
            let body = current_body.trim().to_string();
            if !body.is_empty() {
                sections.push(MarkdownSection {
                    name: current_name.clone(),
                    scopes: current_scopes.clone(),
                    content: body,
                });
            }
            current_body.clear();

            // Parse heading: "# Title <!-- scope: /path -->"
            // or multi-scope: "# Title <!-- scope: /finance, /legal -->"
            if let Some(scope_start) = line.find("<!-- scope:") {
                let after = &line[scope_start + 11..];
                if let Some(scope_end) = after.find("-->") {
                    current_scopes = after[..scope_end]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
                current_name = line[..scope_start]
                    .trim_start_matches('#')
                    .trim()
                    .to_string();
            } else {
                current_name = line.trim_start_matches('#').trim().to_string();
                current_scopes = vec!["/".to_string()];
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
            scopes: current_scopes,
            content: body,
        });
    }

    sections
}

fn main() {
    scope_based_example();
    println!("\n{}\n", "=".repeat(72));
    mixed_mode_example();
}

/// Original example: each section has a single scope, using scope-based encryption.
fn scope_based_example() {
    println!(">>> EXAMPLE 1: Pure scope-based (single scope per section)\n");

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

    let sections = parse_markdown(document);
    println!("Parsed {} sections:\n", sections.len());
    for s in &sections {
        println!(
            "  [{}] scopes={:?} ({} bytes)",
            s.name,
            s.scopes,
            s.content.len()
        );
    }

    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);

    let mut builder = SectionedEnvelopeBuilder::new();
    for s in &sections {
        let scope = Scope::new(&s.scopes[0]).unwrap();
        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope)
            .set_spend_key(&spend)
            .set_scope_based()
            .encrypt(s.content.as_bytes(), &mut rng)
            .unwrap();
        builder.add_section(s.name.clone(), envelope).unwrap();
    }
    let sectioned = builder.build().unwrap();

    let bytes = sectioned.to_bytes();
    println!(
        "\nEncrypted sectioned envelope: {} bytes total",
        bytes.len()
    );

    let root_read = spend.derive_root_read_key();
    let finance_key = root_read.derive_child_segment("finance").unwrap();
    let legal_key = root_read.derive_child_segment("legal").unwrap();
    let engineering_key = root_read.derive_child_segment("engineering").unwrap();

    let pre_finance_detailed = finance_key.derive_child_segment("detailed").unwrap();
    println!(
        "\nPre-encryption /finance/detailed key:  key_id={}",
        pre_finance_detailed.key_id()
    );

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

    println!("\n--- Post-encryption key derivation ---");
    let post_spend = SpendKeyPair::from_seed(&[42u8; 32]);
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

/// New example: mixing scope-based and recipient-based encryption.
///
/// Sections with a single scope use scope-based mode (deterministic, post-encryption derivation).
/// Sections with multiple scopes use recipient mode (explicit key list per cross-scope section).
fn mixed_mode_example() {
    println!(">>> EXAMPLE 2: Mixed mode (cross-scope sections via recipient mode)\n");

    let document = r#"# Company Report <!-- scope: / -->
This is the public introduction visible to all key holders.

## Finance Summary <!-- scope: /finance -->
Revenue: $4.2M this quarter.
Burn rate is decreasing. Runway extended to 18 months.

## Legal <!-- scope: /legal -->
Pending litigation: 2 cases.
IP portfolio: 12 patents filed, 4 granted.

## Joint Compliance Review <!-- scope: /finance, /legal -->
Cross-department compliance findings:
- SOX audit passed for finance controls.
- Legal cleared all pending regulatory items.
This section is accessible to BOTH finance and legal, but NOT engineering.

## Engineering <!-- scope: /engineering -->
Sprint velocity: 42 points/week.
Next milestone: v2.0 launch in Q3.
"#;

    let sections = parse_markdown(document);
    println!("Parsed {} sections:\n", sections.len());
    for s in &sections {
        let mode = if s.scopes.len() > 1 {
            "recipient"
        } else {
            "scope-based"
        };
        println!(
            "  [{}] scopes={:?} -> {} mode ({} bytes)",
            s.name,
            s.scopes,
            mode,
            s.content.len()
        );
    }

    let mut rng = rand::thread_rng();
    let spend = SpendKeyPair::from_seed(&[42u8; 32]);
    let root_read = spend.derive_root_read_key();

    // Pre-derive scope keys for recipient mode sections
    let scope_keys: std::collections::HashMap<String, ReadKeyPair> =
        ["/finance", "/legal", "/engineering"]
            .iter()
            .map(|s| {
                let key = root_read
                    .derive_child_segment(s.trim_start_matches('/'))
                    .unwrap();
                (s.to_string(), key)
            })
            .collect();

    let mut builder = SectionedEnvelopeBuilder::new();
    for s in &sections {
        let envelope = if s.scopes.len() == 1 {
            // Single scope: use scope-based mode (supports post-encryption key derivation)
            let scope = Scope::new(&s.scopes[0]).unwrap();
            EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope)
                .set_spend_key(&spend)
                .set_scope_based()
                .encrypt(s.content.as_bytes(), &mut rng)
                .unwrap()
        } else {
            // Multiple scopes: use recipient mode with explicit keys.
            // Include root so the root key holder retains access to everything.
            let mut recipients: Vec<Recipient> = vec![Recipient {
                read_public_key: *root_read.public_key(),
                key_id: root_read.key_id(),
            }];
            recipients.extend(s.scopes.iter().map(|scope_str| {
                let key = &scope_keys[scope_str.as_str()];
                Recipient {
                    read_public_key: *key.public_key(),
                    key_id: key.key_id(),
                }
            }));

            let mut eb = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root());
            eb.add_recipients(&recipients).set_spend_key(&spend);
            eb.encrypt(s.content.as_bytes(), &mut rng).unwrap()
        };
        builder.add_section(s.name.clone(), envelope).unwrap();
    }
    let mut sectioned = builder.build().unwrap();

    let bytes = sectioned.to_bytes();
    println!(
        "\nEncrypted sectioned envelope: {} bytes total",
        bytes.len()
    );

    let finance_key = root_read.derive_child_segment("finance").unwrap();
    let legal_key = root_read.derive_child_segment("legal").unwrap();
    let engineering_key = root_read.derive_child_segment("engineering").unwrap();

    println!("\n--- Decrypt with ROOT key (has access to everything) ---");
    decrypt_sections(&sectioned, &root_read, &spend);

    println!("\n--- Decrypt with FINANCE key ---");
    println!("  (should see: Finance Summary, Joint Compliance Review)");
    decrypt_sections(&sectioned, &finance_key, &spend);

    println!("\n--- Decrypt with LEGAL key ---");
    println!("  (should see: Legal, Joint Compliance Review)");
    decrypt_sections(&sectioned, &legal_key, &spend);

    println!("\n--- Decrypt with ENGINEERING key ---");
    println!("  (should see: Engineering only — NO joint compliance)");
    decrypt_sections(&sectioned, &engineering_key, &spend);

    // --- Step: Rekey the Joint Compliance Review section ---
    // Change access from [root, finance, legal] to [root, legal, engineering]
    println!("\n--- REKEY: Joint Compliance Review ---");
    println!("  Changing access: [root, finance, legal] -> [root, legal, engineering]");
    println!("  (ciphertext stays the same, only access entries + signature change)\n");

    let new_recipients = vec![
        Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        },
        Recipient {
            read_public_key: *legal_key.public_key(),
            key_id: legal_key.key_id(),
        },
        Recipient {
            read_public_key: *engineering_key.public_key(),
            key_id: engineering_key.key_id(),
        },
    ];

    // Use root_read (an existing recipient) to authorize the rekey
    sectioned
        .rekey_section(
            "Joint Compliance Review",
            &root_read,
            &new_recipients,
            &spend,
            &mut rng,
        )
        .unwrap();

    println!("--- After rekey: Decrypt with FINANCE key ---");
    println!("  (should LOSE access to Joint Compliance Review)");
    decrypt_sections(&sectioned, &finance_key, &spend);

    println!("\n--- After rekey: Decrypt with LEGAL key ---");
    println!("  (should KEEP access to Joint Compliance Review)");
    decrypt_sections(&sectioned, &legal_key, &spend);

    println!("\n--- After rekey: Decrypt with ENGINEERING key ---");
    println!("  (should GAIN access to Joint Compliance Review)");
    decrypt_sections(&sectioned, &engineering_key, &spend);
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
