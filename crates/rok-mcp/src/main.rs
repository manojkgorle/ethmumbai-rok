mod resources;
mod session;
mod tools;

use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use session::SessionConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr only — stdout is the JSON-RPC transport
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("rok-mcp server starting");

    // Pre-load config from ~/.rok/session.json if available
    let config = SessionConfig::load();
    if config.is_some() {
        tracing::info!("loaded credentials from ~/.rok/session.json");
    }

    let service = tools::RokService::new_with_config(config);
    let server = service.serve(rmcp::transport::io::stdio()).await?;
    server.waiting().await?;

    Ok(())
}
