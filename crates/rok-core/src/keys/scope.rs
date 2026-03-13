use crate::error::{Result, RokError};
use serde::{Deserialize, Serialize};

/// A validated hierarchical scope path.
///
/// Scopes define the access boundary for read keys. A read key at scope `/finance`
/// can access data at `/finance` and any descendant (e.g., `/finance/q1`), but not
/// at `/legal` or `/`.
///
/// Rules:
/// - Must start with `/`
/// - Only ASCII alphanumeric, `-`, `_`, `/` allowed
/// - No double slashes, no trailing slash (except root `/`)
/// - Root scope is `/`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope(String);

impl Scope {
    /// The root scope `/`, which is ancestor of all other scopes.
    pub fn root() -> Self {
        Scope("/".to_string())
    }

    /// Create a new scope from a path string, validating it.
    pub fn new(path: &str) -> Result<Self> {
        if path.is_empty() {
            return Err(RokError::InvalidScope("scope cannot be empty".into()));
        }
        if !path.starts_with('/') {
            return Err(RokError::InvalidScope("scope must start with '/'".into()));
        }
        if path.len() > 1 && path.ends_with('/') {
            return Err(RokError::InvalidScope(
                "scope must not end with '/' (except root)".into(),
            ));
        }
        if path.contains("//") {
            return Err(RokError::InvalidScope(
                "scope must not contain double slashes".into(),
            ));
        }

        // Validate each character
        for (i, ch) in path.chars().enumerate() {
            if i == 0 {
                continue; // leading '/' already validated
            }
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '/' {
                return Err(RokError::InvalidScope(format!(
                    "invalid character '{}' at position {}",
                    ch, i
                )));
            }
        }

        // Validate no empty segments (already covered by // check, but be safe)
        if path != "/" {
            for segment in path[1..].split('/') {
                if segment.is_empty() {
                    return Err(RokError::InvalidScope(
                        "scope contains empty segment".into(),
                    ));
                }
            }
        }

        Ok(Scope(path.to_string()))
    }

    /// Check if this scope is an ancestor of (or equal to) the given descendant scope.
    ///
    /// A scope is its own ancestor. Root `/` is ancestor of everything.
    /// `/finance` is ancestor of `/finance/q1` but NOT of `/legal`.
    pub fn is_ancestor_of(&self, descendant: &Scope) -> bool {
        if self.0 == "/" {
            return true;
        }
        if self.0 == descendant.0 {
            return true;
        }
        // Check that descendant starts with self + "/"
        descendant.0.starts_with(&self.0)
            && descendant.0.as_bytes().get(self.0.len()) == Some(&b'/')
    }

    /// Return the depth of the scope (number of path segments).
    /// Root `/` has depth 0. `/finance` has depth 1. `/finance/q1` has depth 2.
    pub fn depth(&self) -> usize {
        if self.0 == "/" {
            0
        } else {
            self.0[1..].split('/').count()
        }
    }

    /// Return the path components (excluding the leading `/`).
    /// Root returns an empty vec. `/finance/q1` returns `["finance", "q1"]`.
    pub fn components(&self) -> Vec<&str> {
        if self.0 == "/" {
            Vec::new()
        } else {
            self.0[1..].split('/').collect()
        }
    }

    /// Return the parent scope, or None if this is the root.
    pub fn parent(&self) -> Option<Scope> {
        if self.0 == "/" {
            return None;
        }
        match self.0.rfind('/') {
            Some(0) => Some(Scope::root()),
            Some(pos) => Some(Scope(self.0[..pos].to_string())),
            None => None,
        }
    }

    /// Create a child scope by appending a segment.
    pub fn child(&self, segment: &str) -> Result<Scope> {
        if segment.is_empty() {
            return Err(RokError::InvalidScope("segment cannot be empty".into()));
        }
        if segment.contains('/') {
            return Err(RokError::InvalidScope(
                "segment must not contain '/'".into(),
            ));
        }
        for ch in segment.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(RokError::InvalidScope(format!(
                    "invalid character '{}' in segment",
                    ch
                )));
            }
        }

        let path = if self.0 == "/" {
            format!("/{}", segment)
        } else {
            format!("{}/{}", self.0, segment)
        };
        Ok(Scope(path))
    }

    /// Return the scope path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_scope() {
        let root = Scope::root();
        assert_eq!(root.as_str(), "/");
        assert_eq!(root.depth(), 0);
        assert!(root.components().is_empty());
        assert!(root.parent().is_none());
    }

    #[test]
    fn test_valid_scopes() {
        assert!(Scope::new("/").is_ok());
        assert!(Scope::new("/finance").is_ok());
        assert!(Scope::new("/finance/q1").is_ok());
        assert!(Scope::new("/a-b_c/d123").is_ok());
    }

    #[test]
    fn test_invalid_scopes() {
        assert!(Scope::new("").is_err());
        assert!(Scope::new("finance").is_err()); // no leading /
        assert!(Scope::new("/finance/").is_err()); // trailing /
        assert!(Scope::new("//").is_err()); // double slash
        assert!(Scope::new("/finance//q1").is_err());
        assert!(Scope::new("/finance/q 1").is_err()); // space
        assert!(Scope::new("/finance/q!1").is_err()); // special char
    }

    #[test]
    fn test_is_ancestor_of() {
        let root = Scope::root();
        let finance = Scope::new("/finance").unwrap();
        let finance_q1 = Scope::new("/finance/q1").unwrap();
        let legal = Scope::new("/legal").unwrap();

        // Root is ancestor of everything
        assert!(root.is_ancestor_of(&root));
        assert!(root.is_ancestor_of(&finance));
        assert!(root.is_ancestor_of(&finance_q1));
        assert!(root.is_ancestor_of(&legal));

        // /finance is ancestor of /finance and /finance/q1
        assert!(finance.is_ancestor_of(&finance));
        assert!(finance.is_ancestor_of(&finance_q1));
        assert!(!finance.is_ancestor_of(&root));
        assert!(!finance.is_ancestor_of(&legal));

        // /finance/q1 is only ancestor of itself
        assert!(finance_q1.is_ancestor_of(&finance_q1));
        assert!(!finance_q1.is_ancestor_of(&finance));
    }

    #[test]
    fn test_no_prefix_confusion() {
        // /fin should NOT be ancestor of /finance
        let fin = Scope::new("/fin").unwrap();
        let finance = Scope::new("/finance").unwrap();
        assert!(!fin.is_ancestor_of(&finance));
    }

    #[test]
    fn test_depth() {
        assert_eq!(Scope::root().depth(), 0);
        assert_eq!(Scope::new("/a").unwrap().depth(), 1);
        assert_eq!(Scope::new("/a/b").unwrap().depth(), 2);
        assert_eq!(Scope::new("/a/b/c").unwrap().depth(), 3);
    }

    #[test]
    fn test_components() {
        assert_eq!(Scope::root().components(), Vec::<&str>::new());
        assert_eq!(
            Scope::new("/finance").unwrap().components(),
            vec!["finance"]
        );
        assert_eq!(
            Scope::new("/finance/q1").unwrap().components(),
            vec!["finance", "q1"]
        );
    }

    #[test]
    fn test_parent() {
        assert_eq!(Scope::root().parent(), None);
        assert_eq!(
            Scope::new("/finance").unwrap().parent(),
            Some(Scope::root())
        );
        assert_eq!(
            Scope::new("/finance/q1").unwrap().parent(),
            Some(Scope::new("/finance").unwrap())
        );
    }

    #[test]
    fn test_child() {
        let root = Scope::root();
        let finance = root.child("finance").unwrap();
        assert_eq!(finance.as_str(), "/finance");

        let q1 = finance.child("q1").unwrap();
        assert_eq!(q1.as_str(), "/finance/q1");

        // Invalid children
        assert!(root.child("").is_err());
        assert!(root.child("a/b").is_err());
        assert!(root.child("a b").is_err());
    }
}
