//! CLI entry: wires RTDS (fast CEX) + CLOB websocket (Polymarket) + optional FOK execution.
//!
//! Related upstream projects (from Polymarket ecosystem / community):
//! - `https://github.com/warproxxx/poly_data` — historical trades for research
//! - `https://github.com/Polymarket/polymarket-cli` — market inspection
//! - `https://github.com/Polymarket/agents` — agent-style orchestration examples
//! - `https://github.com/Polymarket/rs-clob-client` — this binary builds on the official Rust CLOB SDK

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use polymarket_lag_arb::config::Config;
use polymarket_lag_arb::engine;
use polymarket_lag_arb::execution;
use polymarket_lag_arb::feeds;

#[derive(Parser, Debug)]
#[command(name = "polymarket-lag-arb")]
struct Cli {
    /// Turn on authenticated trading (requires `POLYMARKET_PRIVATE_KEY` and allowances).
    #[arg(long)]
    live: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut cfg = Config::from_env()?;
    if cli.live {
        cfg.live = true;
    }

    let state = feeds::shared_state();

    let sym = cfg.cex_symbol.clone();
    let horizon = cfg.ref_horizon;
    let tok = cfg.yes_token_id.clone();
    let st_rtds = state.clone();
    tokio::spawn(async move {
        if let Err(e) = feeds::run_rtds_btcusd(st_rtds, sym, horizon).await {
            tracing::error!(error = %e, "RTDS feed task exited");
        }
    });
    let st_ws = state.clone();
    tokio::spawn(async move {
        if let Err(e) = feeds::run_clob_orderbook(st_ws, tok).await {
            tracing::error!(error = %e, "CLOB websocket task exited");
        }
    });

    let live = if cfg.live {
        Some(execution::connect().await?)
    } else {
        None
    };

    engine::run_loop(cfg, state, live).await;
    Ok(())
}
