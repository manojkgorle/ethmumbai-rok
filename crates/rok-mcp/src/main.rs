mod resources;
mod session;
mod tools;

use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use session::SessionConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // --dump: print all memories to stdout and exit (used by hooks for context injection)
    if args.iter().any(|a| a == "--dump") {
        return dump_memories();
    }

    // Log to stderr only — stdout is the JSON-RPC transport
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("rok-mcp server starting");

    let config = SessionConfig::load();
    if config.is_some() {
        tracing::info!("loaded credentials from ~/.rok/session.json");
    }

    let service = tools::RokService::new_with_config(config);
    let server = service.serve(rmcp::transport::io::stdio()).await?;
    server.waiting().await?;

    Ok(())
}

/// Load all memories from Fileverse and print them to stdout.
/// Used by the auto-load hook to inject memory content into Claude's context.
fn dump_memories() -> anyhow::Result<()> {
    let config = SessionConfig::load()
        .ok_or_else(|| anyhow::anyhow!("no ~/.rok/session.json found"))?;

    let auto_load = config.auto_load.unwrap_or(false);
    if !auto_load {
        return Ok(());
    }

    let session = tools::RokService::build_session_from_config(config)
        .ok_or_else(|| anyhow::anyhow!("invalid credentials in session.json"))?;

    let reader = session.memory_reader()?;
    let read_key = session.read_key()?;
    let entries = reader.list(&read_key).map_err(|e| anyhow::anyhow!("{e}"))?;

    if entries.is_empty() {
        return Ok(());
    }

    println!("[rok-memory] {} memories loaded from scope {}:\n", entries.len(), session.scope);
    for entry in &entries {
        let text = String::from_utf8_lossy(&entry.data);
        println!("--- {} / {} ---", entry.scope, entry.key);
        println!("{}", text);
        println!();
    }

    Ok(())
}
