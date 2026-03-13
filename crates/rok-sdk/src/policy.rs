use serde::{Deserialize, Serialize};

use rok_core::keys::key_id::KeyId;
use rok_core::keys::scope::Scope;

/// Declarative mapping of scopes to authorized read keys.
///
/// Used by the Vault and Pipeline to automatically determine
/// which recipients should receive access to data at a given scope.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessPolicy {
    rules: Vec<AccessRule>,
}

/// A single access rule: maps a scope to recipients with optional expiry.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessRule {
    pub scope: String,
    pub recipient_key_ids: Vec<String>, // base58-encoded KeyIds
    pub expires_at: Option<u64>,        // Unix timestamp, 0 = no expiry
}

impl AccessPolicy {
    /// Create a new empty policy.
    pub fn new() -> Self {
        AccessPolicy { rules: Vec::new() }
    }

    /// Grant access at a scope to a recipient key.
    pub fn grant(&mut self, scope: &Scope, key_id: &KeyId, expires_at: Option<u64>) {
        // Check if rule already exists for this scope
        let scope_str = scope.as_str().to_string();
        let key_str = key_id.to_base58();

        if let Some(rule) = self.rules.iter_mut().find(|r| r.scope == scope_str) {
            if !rule.recipient_key_ids.contains(&key_str) {
                rule.recipient_key_ids.push(key_str);
            }
        } else {
            self.rules.push(AccessRule {
                scope: scope_str,
                recipient_key_ids: vec![key_str],
                expires_at,
            });
        }
    }

    /// Revoke a specific key's access at a scope.
    pub fn revoke(&mut self, scope: &Scope, key_id: &KeyId) {
        let scope_str = scope.as_str();
        let key_str = key_id.to_base58();

        if let Some(rule) = self.rules.iter_mut().find(|r| r.scope == scope_str) {
            rule.recipient_key_ids.retain(|k| k != &key_str);
        }
    }

    /// Get all recipient key IDs for a given scope.
    ///
    /// Returns keys from the exact scope AND any ancestor scope rules.
    pub fn key_ids_for_scope(&self, scope: &Scope) -> Vec<String> {
        let target = scope.as_str();
        let mut result = Vec::new();

        for rule in &self.rules {
            // Check if rule scope is an ancestor of or equal to target
            if let Ok(rule_scope) = Scope::new(&rule.scope) {
                if rule_scope.is_ancestor_of(scope) || rule.scope == target {
                    // Skip expired rules
                    if let Some(expires) = rule.expires_at {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        if now > expires {
                            continue;
                        }
                    }
                    result.extend(rule.recipient_key_ids.iter().cloned());
                }
            }
        }

        result.sort();
        result.dedup();
        result
    }

    /// Serialize the policy to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Return all rules.
    pub fn rules(&self) -> &[AccessRule] {
        &self.rules
    }

    /// Serialize the policy to protobuf bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        let proto = self.to_proto();
        proto.to_proto_bytes()
    }

    /// Deserialize from protobuf bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> std::result::Result<Self, rok_core::error::RokError> {
        let proto = rok_core::proto::rok::AccessPolicy::from_proto_bytes(bytes)?;
        Self::from_proto(&proto)
    }

    fn to_proto(&self) -> rok_core::proto::rok::AccessPolicy {
        rok_core::proto::rok::AccessPolicy {
            rules: self
                .rules
                .iter()
                .map(|r| rok_core::proto::rok::AccessRule {
                    scope: r.scope.clone(),
                    recipient_key_ids: r
                        .recipient_key_ids
                        .iter()
                        .map(|kid_b58| {
                            KeyId::from_base58(kid_b58)
                                .map(|kid| kid.as_bytes().to_vec())
                                .unwrap_or_default()
                        })
                        .collect(),
                    expires_at: r.expires_at.unwrap_or(0),
                })
                .collect(),
        }
    }

    fn from_proto(
        proto: &rok_core::proto::rok::AccessPolicy,
    ) -> std::result::Result<Self, rok_core::error::RokError> {
        let rules = proto
            .rules
            .iter()
            .map(|r| {
                let recipient_key_ids = r
                    .recipient_key_ids
                    .iter()
                    .map(|bytes| {
                        if bytes.len() == 8 {
                            let mut arr = [0u8; 8];
                            arr.copy_from_slice(bytes);
                            KeyId::from_bytes(arr).to_base58()
                        } else {
                            String::new()
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                AccessRule {
                    scope: r.scope.clone(),
                    recipient_key_ids,
                    expires_at: if r.expires_at == 0 {
                        None
                    } else {
                        Some(r.expires_at)
                    },
                }
            })
            .collect();
        Ok(AccessPolicy { rules })
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grant_and_lookup() {
        let mut policy = AccessPolicy::new();
        let scope = Scope::new("/finance").unwrap();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);

        policy.grant(&scope, &kid, None);

        let keys = policy.key_ids_for_scope(&scope);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], kid.to_base58());
    }

    #[test]
    fn test_ancestor_scope_includes() {
        let mut policy = AccessPolicy::new();
        let root = Scope::root();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);

        // Grant at root
        policy.grant(&root, &kid, None);

        // Should be returned for /finance (descendant of root)
        let finance = Scope::new("/finance").unwrap();
        let keys = policy.key_ids_for_scope(&finance);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_revoke() {
        let mut policy = AccessPolicy::new();
        let scope = Scope::new("/finance").unwrap();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);

        policy.grant(&scope, &kid, None);
        assert_eq!(policy.key_ids_for_scope(&scope).len(), 1);

        policy.revoke(&scope, &kid);
        assert_eq!(policy.key_ids_for_scope(&scope).len(), 0);
    }

    #[test]
    fn test_json_roundtrip() {
        let mut policy = AccessPolicy::new();
        let scope = Scope::new("/finance").unwrap();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        policy.grant(&scope, &kid, None);

        let json = policy.to_json().unwrap();
        let restored = AccessPolicy::from_json(&json).unwrap();

        assert_eq!(restored.rules().len(), 1);
        assert_eq!(
            restored.key_ids_for_scope(&scope),
            policy.key_ids_for_scope(&scope)
        );
    }

    #[test]
    fn test_proto_roundtrip() {
        let mut policy = AccessPolicy::new();
        let scope = Scope::new("/finance").unwrap();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        policy.grant(&scope, &kid, None);

        let bytes = policy.to_proto_bytes();
        let restored = AccessPolicy::from_proto_bytes(&bytes).unwrap();

        assert_eq!(restored.rules().len(), 1);
        assert_eq!(
            restored.key_ids_for_scope(&scope),
            policy.key_ids_for_scope(&scope)
        );
    }

    #[test]
    fn test_no_duplicate_grants() {
        let mut policy = AccessPolicy::new();
        let scope = Scope::new("/finance").unwrap();
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);

        policy.grant(&scope, &kid, None);
        policy.grant(&scope, &kid, None); // duplicate

        assert_eq!(policy.key_ids_for_scope(&scope).len(), 1);
    }
}
