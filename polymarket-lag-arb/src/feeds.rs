use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use futures::StreamExt as _;
use parking_lot::Mutex;
use polymarket_client_sdk::clob::ws::Client as WsClient;
use polymarket_client_sdk::rtds::Client as RtdsClient;
use polymarket_client_sdk::types::U256;
use rust_decimal::prelude::ToPrimitive as _;
use tracing::{debug, error, info, warn};

/// Shared cross-feed snapshot used by the engine.
#[derive(Debug, Default, Clone)]
pub struct MarketState {
    pub cex_price: Option<f64>,
    pub cex_updated: Option<Instant>,
    pub cex_ref_price: Option<f64>,
    pub cex_ref_instant: Option<Instant>,
    pub pm_bid: Option<f64>,
    pub pm_ask: Option<f64>,
    pub pm_updated: Option<Instant>,
}

pub type SharedState = Arc<Mutex<MarketState>>;

pub fn shared_state() -> SharedState {
    Arc::new(Mutex::new(MarketState::default()))
}

pub async fn run_rtds_btcusd(state: SharedState, symbol: String, horizon: std::time::Duration) -> Result<()> {
    let client = RtdsClient::default();
    let sym = symbol.to_lowercase();
    let stream = client
        .subscribe_crypto_prices(Some(vec![sym.clone()]))
        .with_context(|| format!("subscribe RTDS crypto_prices for {sym}"))?;
    let mut stream = Box::pin(stream);

    info!(symbol = %sym, "RTDS stream started");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(price) => {
                let px = price
                    .value
                    .to_f64()
                    .ok_or_else(|| anyhow::anyhow!("RTDS price not representable as f64"))?;

                let now = Instant::now();
                let mut g = state.lock();
                g.cex_price = Some(px);
                g.cex_updated = Some(now);

                let needs_new_ref = match g.cex_ref_instant {
                    None => true,
                    Some(t) => now.duration_since(t) >= horizon,
                };
                if needs_new_ref {
                    g.cex_ref_price = Some(px);
                    g.cex_ref_instant = Some(now);
                }

                debug!(px, "cex tick");
            }
            Err(e) => warn!(error = %e, "RTDS stream error"),
        }
    }

    // Fail closed: do not leave a stale CEX print usable after the feed dies.
    {
        let mut g = state.lock();
        g.cex_price = None;
        g.cex_updated = None;
        g.cex_ref_price = None;
        g.cex_ref_instant = None;
    }
    warn!("RTDS stream ended; cleared CEX state");
    Ok(())
}

pub async fn run_clob_orderbook(state: SharedState, yes_token_id: String) -> Result<()> {
    let client = WsClient::default();
    let asset = U256::from_str(&yes_token_id).with_context(|| "yes token id must be a base-10 U256")?;
    let stream = client
        .subscribe_orderbook(vec![asset])
        .context("subscribe CLOB orderbook")?;
    let mut stream = Box::pin(stream);

    info!(token_id = %yes_token_id, "CLOB websocket subscribed");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(book) => {
                let now = Instant::now();
                let bid = book.bids.first().and_then(|l| l.price.to_f64());
                let ask = book.asks.first().and_then(|l| l.price.to_f64());

                let mut g = state.lock();
                g.pm_bid = bid;
                g.pm_ask = ask;
                g.pm_updated = Some(now);

                debug!(
                    bid = ?bid,
                    ask = ?ask,
                    bids = book.bids.len(),
                    asks = book.asks.len(),
                    "pm book"
                );
            }
            Err(e) => error!(error = %e, "CLOB websocket error"),
        }
    }

    warn!("CLOB websocket stream ended");
    Ok(())
}
