use rok_core::error::{Result, RokError};

use super::{StorageBackend, StorageEntry, StorageId};

/// Fileverse-backed storage using the local `@fileverse/api` REST server.
///
/// Stores rok `EncryptedEnvelope` bytes as base64-encoded dDocs via HTTP.
/// Title convention: `rok:{scope}:{key}` for lookup by scope+key.
/// Fileverse never sees plaintext — all encryption happens in the rok layer.
pub struct FileverseBackend {
    base_url: String,
    api_key: String,
    client: reqwest::blocking::Client,
}

// --- Fileverse API response types ---

#[derive(serde::Deserialize)]
struct CreateResponse {
    data: CreateData,
}

#[derive(serde::Deserialize)]
struct CreateData {
    #[serde(alias = "ddocId")]
    ddoc_id: String,
}

#[derive(serde::Deserialize)]
struct DDoc {
    #[serde(alias = "ddocId")]
    ddoc_id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    content: String,
    #[serde(default, alias = "createdAt")]
    created_at: String,
    #[serde(default, alias = "updatedAt")]
    updated_at: String,
}

#[derive(serde::Deserialize)]
struct ListResponse {
    ddocs: Vec<DDoc>,
}

#[derive(serde::Deserialize)]
struct SearchResponse {
    nodes: Vec<DDoc>,
}

impl FileverseBackend {
    /// Create a new Fileverse backend pointing at the local API server.
    ///
    /// The `@fileverse/api` package must be running on the specified URL
    /// (default: `http://127.0.0.1:8001`).
    pub fn new(api_key: String) -> Self {
        Self::with_base_url("http://127.0.0.1:8001".to_string(), api_key)
    }

    pub fn with_base_url(base_url: String, api_key: String) -> Self {
        FileverseBackend {
            base_url,
            api_key,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn map_err(e: reqwest::Error) -> RokError {
        RokError::StorageError(format!("fileverse HTTP error: {}", e))
    }

    /// Parse title "rok:{scope}:{key}" into (scope, key).
    fn parse_title(title: &str) -> Option<(String, String)> {
        let rest = title.strip_prefix("rok:")?;
        // Scope starts with / and key is after the last :
        // e.g. "rok:/finance/q1:report" -> ("/finance/q1", "report")
        let colon_pos = rest.rfind(':')?;
        let scope = &rest[..colon_pos];
        let key = &rest[colon_pos + 1..];
        if scope.is_empty() || key.is_empty() {
            return None;
        }
        Some((scope.to_string(), key.to_string()))
    }

    fn ddoc_to_entry(&self, doc: DDoc) -> Result<StorageEntry> {
        let data = BASE64
            .decode(&doc.content)
            .map_err(|e| RokError::StorageError(format!("base64 decode: {}", e)))?;

        let (scope, key) = Self::parse_title(&doc.title)
            .unwrap_or_else(|| ("unknown".to_string(), doc.ddoc_id.clone()));

        // Parse ISO timestamps to unix seconds (best-effort)
        let created_at = parse_timestamp(&doc.created_at);
        let updated_at = parse_timestamp(&doc.updated_at);

        Ok(StorageEntry {
            id: StorageId(doc.ddoc_id),
            scope,
            key,
            data,
            created_at,
            updated_at,
        })
    }
}

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

fn parse_timestamp(s: &str) -> u64 {
    // Try parsing ISO 8601 timestamp, fallback to 0
    // Simple approach: look for seconds since epoch or parse manually
    s.parse::<u64>().unwrap_or(0)
}

impl StorageBackend for FileverseBackend {
    fn put(&self, scope: &str, key: &str, data: &[u8]) -> Result<StorageId> {
        let encoded = BASE64.encode(data);
        let title = format!("rok:{}:{}", scope, key);

        // Check if document already exists (update instead of create)
        if let Ok(existing) = self.get_by_key(scope, key) {
            // Update existing document
            let body = serde_json::json!({
                "title": title,
                "content": encoded,
            });

            let resp = self
                .client
                .put(format!("{}/api/ddocs/{}", self.base_url, existing.id.0))
                .query(&[("apiKey", &self.api_key)])
                .json(&body)
                .send()
                .map_err(Self::map_err)?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                return Err(RokError::StorageError(format!(
                    "fileverse PUT update failed ({}): {}",
                    status, text
                )));
            }

            return Ok(existing.id);
        }

        // Create new document
        let body = serde_json::json!({
            "title": title,
            "content": encoded,
        });

        let resp = self
            .client
            .post(format!("{}/api/ddocs", self.base_url))
            .query(&[("apiKey", &self.api_key)])
            .json(&body)
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(RokError::StorageError(format!(
                "fileverse PUT create failed ({}): {}",
                status, text
            )));
        }

        let created: CreateResponse = resp.json().map_err(Self::map_err)?;
        Ok(StorageId(created.data.ddoc_id))
    }

    fn get(&self, id: &StorageId) -> Result<StorageEntry> {
        let resp = self
            .client
            .get(format!("{}/api/ddocs/{}", self.base_url, id.0))
            .query(&[("apiKey", &self.api_key)])
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(RokError::StorageError(format!(
                "fileverse GET failed ({}): {}",
                status, text
            )));
        }

        let doc: DDoc = resp.json().map_err(Self::map_err)?;
        self.ddoc_to_entry(doc)
    }

    fn get_by_key(&self, scope: &str, key: &str) -> Result<StorageEntry> {
        let query = format!("rok:{}:{}", scope, key);
        let resp = self
            .client
            .get(format!("{}/api/search", self.base_url))
            .query(&[("apiKey", &self.api_key), ("q", &query)])
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(RokError::StorageError(format!(
                "fileverse search failed ({}): {}",
                status, text
            )));
        }

        let search: SearchResponse = resp.json().map_err(Self::map_err)?;
        let doc = search
            .nodes
            .into_iter()
            .find(|d| d.title == query)
            .ok_or_else(|| RokError::StorageError(format!("not found: {}:{}", scope, key)))?;

        self.ddoc_to_entry(doc)
    }

    fn list(&self, scope_prefix: &str) -> Result<Vec<StorageEntry>> {
        // Search for all rok documents with this scope prefix
        let query = format!("rok:{}", scope_prefix);
        let resp = self
            .client
            .get(format!("{}/api/search", self.base_url))
            .query(&[
                ("apiKey", &self.api_key),
                ("q", &query),
                ("limit", &"1000".to_string()),
            ])
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            // Fallback: list all and filter client-side
            return self.list_all_and_filter(scope_prefix);
        }

        let search: SearchResponse = resp.json().map_err(Self::map_err)?;
        let mut entries = Vec::new();

        for doc in search.nodes {
            if let Some((scope, _)) = Self::parse_title(&doc.title) {
                if scope == scope_prefix
                    || scope.starts_with(&format!("{}/", scope_prefix))
                    || scope_prefix == "/"
                {
                    if let Ok(entry) = self.ddoc_to_entry(doc) {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }

    fn delete(&self, id: &StorageId) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/api/ddocs/{}", self.base_url, id.0))
            .query(&[("apiKey", &self.api_key)])
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(RokError::StorageError(format!(
                "fileverse DELETE failed ({}): {}",
                status, text
            )));
        }

        Ok(())
    }
}

impl FileverseBackend {
    /// Fallback: list all ddocs and filter by scope prefix client-side.
    fn list_all_and_filter(&self, scope_prefix: &str) -> Result<Vec<StorageEntry>> {
        let resp = self
            .client
            .get(format!("{}/api/ddocs", self.base_url))
            .query(&[("apiKey", &self.api_key), ("limit", &"1000".to_string())])
            .send()
            .map_err(Self::map_err)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(RokError::StorageError(format!(
                "fileverse list failed ({}): {}",
                status, text
            )));
        }

        let list: ListResponse = resp.json().map_err(Self::map_err)?;
        let mut entries = Vec::new();

        for doc in list.ddocs {
            if let Some((scope, _)) = Self::parse_title(&doc.title) {
                if scope == scope_prefix
                    || scope.starts_with(&format!("{}/", scope_prefix))
                    || scope_prefix == "/"
                {
                    if let Ok(entry) = self.ddoc_to_entry(doc) {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_title() {
        let (scope, key) = FileverseBackend::parse_title("rok:/finance:report").unwrap();
        assert_eq!(scope, "/finance");
        assert_eq!(key, "report");

        let (scope, key) = FileverseBackend::parse_title("rok:/finance/q1:summary").unwrap();
        assert_eq!(scope, "/finance/q1");
        assert_eq!(key, "summary");

        let (scope, key) = FileverseBackend::parse_title("rok:/:root-memo").unwrap();
        assert_eq!(scope, "/");
        assert_eq!(key, "root-memo");

        assert!(FileverseBackend::parse_title("not-rok").is_none());
        assert!(FileverseBackend::parse_title("rok::").is_none());
    }
}
