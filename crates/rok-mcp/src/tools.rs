use std::sync::Arc;
use tokio::sync::RwLock;

use rmcp::model::{
    CallToolResult, Content, Implementation, ListResourcesResult, PaginatedRequestParam,
    ReadResourceRequestParam, ReadResourceResult, ResourceContents, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{schemars, serde, tool, Error as McpError, RoleServer};

use rok_core::encoding;
use rok_core::keys::scope::Scope;
use rok_sdk::memory::Proposal;

use crate::resources;
use crate::session::{Role, Session};

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct LoginParams {
    /// Fileverse API key for storage access.
    pub api_key: String,
    /// Fileverse server URL (default: http://127.0.0.1:8001).
    #[serde(default = "default_fileverse_url")]
    pub fileverse_url: String,
    /// Hex-encoded 32-byte spend seed (owner role). Mutually exclusive with read_key.
    #[serde(default)]
    pub spend_seed: Option<String>,
    /// Base58-encoded exported read key (agent role). Requires spend_public.
    #[serde(default)]
    pub read_key: Option<String>,
    /// Base58-encoded spend public key (agent role). Required with read_key.
    #[serde(default)]
    pub spend_public: Option<String>,
    /// Session scope path (default: "/").
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_fileverse_url() -> String {
    "http://127.0.0.1:8001".to_string()
}

fn default_scope() -> String {
    "/".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    /// Hierarchical scope path (e.g. "/engineering/decisions").
    pub scope: String,
    /// Memory name/identifier within the scope.
    pub key: String,
    /// Content to encrypt and store.
    pub content: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ReadParams {
    /// Scope path of the memory to read.
    pub scope: String,
    /// Memory name/identifier to read.
    pub key: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GrantParams {
    /// Scope path to grant access to. The recipient can read this scope and all descendants.
    pub scope: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ProposeParams {
    /// Scope path for the proposed memory.
    pub scope: String,
    /// Memory name/identifier.
    pub key: String,
    /// Content to propose.
    pub content: String,
    /// Identifier of the proposing agent.
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}

fn default_agent_id() -> String {
    "claude-code".to_string()
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RokService {
    session: Arc<RwLock<Option<Session>>>,
}

impl RokService {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            session: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a service with optional pre-loaded config from ~/.rok/session.json.
    /// If config contains valid credentials, bootstraps a session automatically.
    pub fn new_with_config(config: Option<crate::session::SessionConfig>) -> Self {
        let session = config.and_then(|cfg| Self::session_from_config(cfg));
        Self {
            session: Arc::new(RwLock::new(session)),
        }
    }

    fn session_from_config(cfg: crate::session::SessionConfig) -> Option<Session> {
        let url = cfg
            .fileverse_url
            .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
        let api_key = cfg.api_key?;

        if let Some(ref seed_hex) = cfg.spend_seed {
            let seed_bytes = hex::decode(seed_hex).ok()?;
            if seed_bytes.len() != 32 {
                return None;
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            Some(Session::new_owner(seed, Scope::root(), url, api_key))
        } else if let (Some(rk), Some(sp)) = (cfg.read_key, cfg.spend_public) {
            Some(Session::new_agent(rk, sp, Scope::root(), url, api_key))
        } else {
            None
        }
    }

    fn ok(text: impl Into<String>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool(tool_box)]
impl RokService {
    #[tool(description = "Authenticate and start a rok memory session. Provide either spend_seed (owner: full read/write/grant) or read_key + spend_public (agent: read-only).")]
    async fn rok_login(
        &self,
        #[tool(aggr)] params: LoginParams,
    ) -> Result<CallToolResult, McpError> {
        let scope = Scope::new(&params.scope)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        let session = if let Some(ref seed_hex) = params.spend_seed {
            let seed_bytes = hex::decode(seed_hex)
                .map_err(|e| McpError::invalid_params(format!("invalid hex: {e}"), None))?;
            if seed_bytes.len() != 32 {
                return Err(McpError::invalid_params(
                    format!(
                        "spend seed must be 32 bytes (64 hex chars), got {}",
                        seed_bytes.len()
                    ),
                    None,
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            Session::new_owner(seed, scope.clone(), params.fileverse_url, params.api_key)
        } else if let (Some(ref rk), Some(ref sp)) = (&params.read_key, &params.spend_public) {
            Session::new_agent(
                rk.clone(),
                sp.clone(),
                scope.clone(),
                params.fileverse_url,
                params.api_key,
            )
        } else {
            return Err(McpError::invalid_params(
                "provide either spend_seed (owner) or read_key + spend_public (agent)",
                None,
            ));
        };

        let role = session.role;
        let count = Self::count_memories(&session)
            .map_err(|e| McpError::internal_error(format!("login failed: {e}"), None))?;

        let mut guard = self.session.write().await;
        let mut session = session;
        session.memory_count = count;
        *guard = Some(session);

        Self::ok(format!(
            "rok session started\n  role: {role}\n  scope: {scope}\n  memories: {count}"
        ))
    }

    #[tool(description = "End the rok memory session and clear credentials")]
    async fn rok_logout(&self) -> Result<CallToolResult, McpError> {
        let mut guard = self.session.write().await;
        if guard.is_none() {
            return Err(McpError::invalid_params("no active session", None));
        }
        *guard = None;
        Self::ok("rok session ended, credentials cleared")
    }

    #[tool(description = "List all accessible encrypted memories")]
    async fn rok_list(&self) -> Result<CallToolResult, McpError> {
        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::invalid_params("no active session — call rok_login first", None))?;

        let reader = session
            .memory_reader()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let read_key = session
            .read_key()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let entries = reader
            .list(&read_key)
            .map_err(|e| McpError::internal_error(format!("list failed: {e}"), None))?;

        if entries.is_empty() {
            return Self::ok("no memories found");
        }

        let mut lines = vec![format!("memories ({}):", entries.len())];
        for e in &entries {
            let preview = String::from_utf8_lossy(&e.data);
            let preview = if preview.len() > 120 {
                format!("{}…", &preview[..120])
            } else {
                preview.to_string()
            };
            lines.push(format!("  [{scope}] {key} = {preview}", scope = e.scope, key = e.key));
        }
        Self::ok(lines.join("\n"))
    }

    #[tool(description = "Read and decrypt a memory by scope and key")]
    async fn rok_read(
        &self,
        #[tool(aggr)] params: ReadParams,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::invalid_params("no active session — call rok_login first", None))?;

        let scope = Scope::new(&params.scope)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        let reader = session
            .memory_reader()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let read_key = session
            .read_key()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let data = reader
            .read(&read_key, &scope, &params.key)
            .map_err(|e| McpError::internal_error(format!("read failed: {e}"), None))?;

        Self::ok(String::from_utf8_lossy(&data))
    }

    #[tool(description = "Encrypt and store a memory (owner only)")]
    async fn rok_write(
        &self,
        #[tool(aggr)] params: WriteParams,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::invalid_params("no active session — call rok_login first", None))?;

        if session.role != Role::Owner {
            return Err(McpError::invalid_params(
                "write requires owner role — use rok_propose to stage changes as agent",
                None,
            ));
        }

        let scope = Scope::new(&params.scope)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        let store = session
            .memory_store()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let id = store
            .write(&scope, &params.key, params.content.as_bytes())
            .map_err(|e| McpError::internal_error(format!("write failed: {e}"), None))?;

        Self::ok(format!(
            "stored {scope}:{key} (id: {id})",
            scope = params.scope,
            key = params.key,
            id = id.0
        ))
    }

    #[tool(description = "Grant read access to a scope by exporting a scoped key (owner only)")]
    async fn rok_grant(
        &self,
        #[tool(aggr)] params: GrantParams,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::invalid_params("no active session — call rok_login first", None))?;

        if session.role != Role::Owner {
            return Err(McpError::invalid_params(
                "grant requires owner role (spend seed)",
                None,
            ));
        }

        let scope = Scope::new(&params.scope)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        let store = session
            .memory_store()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let exported = store
            .grant_access(&scope)
            .map_err(|e| McpError::internal_error(format!("grant failed: {e}"), None))?;

        let encoded_key = encoding::encode_exported_read_key(&exported);
        let spend_public = encoding::encode_spend_public(
            &session
                .spend_key()
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
                .verifying_key(),
        );

        Self::ok(format!(
            "granted access to {scope}\n  read_key: {encoded_key}\n  spend_public: {spend_public}\n\n\
             Give both values to the agent. They can read {scope} and descendants.",
            scope = params.scope
        ))
    }

    #[tool(description = "Propose a memory write (agent) or accept a proposal (owner)")]
    async fn rok_propose(
        &self,
        #[tool(aggr)] params: ProposeParams,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::invalid_params("no active session — call rok_login first", None))?;

        let scope = Scope::new(&params.scope)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        match session.role {
            Role::Owner => {
                let store = session
                    .memory_store()
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let proposal = Proposal {
                    scope,
                    key: params.key.clone(),
                    plaintext: params.content.into_bytes(),
                    proposed_by: params.agent_id.clone(),
                };
                let id = store
                    .accept_proposal(&proposal)
                    .map_err(|e| McpError::internal_error(format!("accept failed: {e}"), None))?;
                Self::ok(format!(
                    "accepted proposal from '{}' at {}:{} (id: {})",
                    params.agent_id, params.scope, params.key, id.0
                ))
            }
            Role::Agent => Self::ok(format!(
                "proposal staged (agent cannot write directly)\n  scope: {}\n  key: {}\n  from: {}\n  size: {} bytes\n\n\
                 The owner must accept this with rok_propose using their spend seed.",
                params.scope,
                params.key,
                params.agent_id,
                params.content.len()
            )),
        }
    }

    #[tool(description = "Show current rok session status")]
    async fn rok_status(&self) -> String {
        let guard = self.session.read().await;
        match guard.as_ref() {
            Some(session) => {
                let capabilities = match session.role {
                    Role::Owner => "read, write, grant, propose",
                    Role::Agent => "read, propose (staged)",
                };
                format!(
                    "rok session active\n  role: {}\n  scope: {}\n  memories: {}\n  capabilities: {capabilities}",
                    session.role, session.scope, session.memory_count
                )
            }
            None => "no active session".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ServerHandler — metadata, capabilities, resources
// ---------------------------------------------------------------------------

#[tool(tool_box)]
impl rmcp::handler::server::ServerHandler for RokService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "rok-mcp: Encrypted hierarchical memory backed by Fileverse. \
                 Call rok_login to start a session, then use rok_list/rok_read/rok_write \
                 to manage memories. Use rok_grant to delegate scoped access."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            server_info: Implementation {
                name: "rok-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            ..Default::default()
        }
    }

    async fn list_resources(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let guard = self.session.read().await;
        let session = match guard.as_ref() {
            Some(s) => s,
            None => {
                return Ok(ListResourcesResult {
                    next_cursor: None,
                    resources: vec![],
                })
            }
        };

        let reader = session
            .memory_reader()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let read_key = session
            .read_key()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let entries = reader
            .list(&read_key)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let resources: Vec<_> = entries.iter().map(resources::memory_to_resource).collect();

        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let uri = &request.uri;

        // Parse URI: rok://memory/{scope}/{key}
        let path = uri
            .strip_prefix("rok://memory")
            .ok_or_else(|| McpError::invalid_params(format!("invalid URI: {uri}"), None))?;

        let (scope_str, key) = match path.rsplit_once('/') {
            Some((s, k)) if !k.is_empty() => (s, k),
            _ => {
                return Err(McpError::invalid_params(
                    format!("URI must be rok://memory/{{scope}}/{{key}}, got: {uri}"),
                    None,
                ))
            }
        };

        let scope_str = if scope_str.is_empty() { "/" } else { scope_str };

        let guard = self.session.read().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| McpError::internal_error("no active session", None))?;

        let scope = Scope::new(scope_str)
            .map_err(|e| McpError::invalid_params(format!("invalid scope: {e}"), None))?;

        let reader = session
            .memory_reader()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let read_key = session
            .read_key()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let data = reader
            .read(&read_key, &scope, key)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = String::from_utf8_lossy(&data).to_string();

        Ok(ReadResourceResult {
            contents: vec![ResourceContents::text(text, uri.clone())],
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl RokService {
    fn count_memories(session: &Session) -> anyhow::Result<usize> {
        let reader = session.memory_reader()?;
        let read_key = session.read_key()?;
        let entries = reader.list(&read_key).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(entries.len())
    }
}
