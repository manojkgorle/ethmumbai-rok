//! Output formatting helpers for CLI display.

#![allow(dead_code)]

use serde::Serialize;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

/// A structured key-value pair for display.
#[derive(Debug, Serialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

/// A structured output section with a title and key-value fields.
#[derive(Debug, Serialize)]
pub struct Section {
    pub title: String,
    pub fields: Vec<KeyValue>,
}

impl Section {
    pub fn new(title: &str) -> Self {
        Section {
            title: title.to_string(),
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.fields.push(KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        });
        self
    }

    /// Print this section in text format.
    pub fn print_text(&self) {
        println!("=== {} ===", self.title);
        for kv in &self.fields {
            println!("  {}: {}", kv.key, kv.value);
        }
    }

    /// Print this section in JSON format.
    pub fn print_json(&self) {
        let map: std::collections::BTreeMap<&str, &str> = self
            .fields
            .iter()
            .map(|kv| (kv.key.as_str(), kv.value.as_str()))
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&map) {
            println!("{}", json);
        }
    }

    /// Print in the specified format.
    pub fn print(&self, format: OutputFormat) {
        match format {
            OutputFormat::Text => self.print_text(),
            OutputFormat::Json => self.print_json(),
        }
    }
}

/// Print a success message.
pub fn success(msg: &str) {
    println!("{}", msg);
}

/// Print an error message to stderr.
pub fn error(msg: &str) {
    eprintln!("error: {}", msg);
}

/// Print a list of items with a title.
pub fn print_list(title: &str, items: &[String]) {
    println!("{}:", title);
    if items.is_empty() {
        println!("  (none)");
    } else {
        for item in items {
            println!("  - {}", item);
        }
    }
}

/// Format bytes as a human-readable size.
pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
