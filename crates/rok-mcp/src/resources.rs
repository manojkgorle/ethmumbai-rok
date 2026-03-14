use rmcp::model::{AnnotateAble, RawResource, Resource};
use rok_sdk::memory::MemoryEntry;

/// Build a resource URI for a memory entry.
pub fn memory_uri(entry: &MemoryEntry) -> String {
    format!("rok://memory{}/{}", entry.scope, entry.key)
}

/// Convert a MemoryEntry to an MCP Resource descriptor.
pub fn memory_to_resource(entry: &MemoryEntry) -> Resource {
    RawResource {
        uri: memory_uri(entry),
        name: format!("{}/{}", entry.scope, entry.key),
        description: Some(format!(
            "Encrypted memory at scope {} ({} bytes)",
            entry.scope,
            entry.data.len()
        )),
        mime_type: Some("text/plain".to_string()),
        size: None,
    }
    .no_annotation()
}
