use std::time::Instant;

use parking_lot::Mutex;
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::config::Config;
use crate::execution;
use crate::feeds::{MarketState, SharedState};
use crate::model::fair_up_probability;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn base_cfg() -> Config {
        Config {
            yes_token_id: "1".into(),
            cex_symbol: "btcusdt".into(),
            min_edge: 0.01,
            k_return: 12.0,
            max_book_staleness: Duration::from_millis(5_000),
            max_cex_staleness: Duration::from_millis(500),
            lag_edge_boost: 0.0,
            order_usdc: 5.0,
            worst_price_slippage: 0.99,
            max_ask_slippage: 0.02,
            cooldown: Duration::from_millis(1),
            ref_horizon: Duration::from_millis(2000),
            only_when_cex_newer: false,
            live: false,
        }
    }

    #[test]
    fn rejects_stale_cex_even_when_book_is_fresh() {
        let cfg = base_cfg();
        let now = Instant::now();
        let s = MarketState {
            cex_price: Some(100.0),
            cex_updated: Some(now - Duration::from_millis(2_000)),
            cex_ref_price: Some(99.0),
            cex_ref_instant: Some(now - Duration::from_millis(2_000)),
            pm_bid: Some(0.40),
            pm_ask: Some(0.42),
            pm_updated: Some(now),
        };
        assert!(evaluate(&cfg, &s).is_none());
    }

    #[test]
    fn accepts_fresh_cex_and_book() {
        let cfg = base_cfg();
        let now = Instant::now();
        let s = MarketState {
            cex_price: Some(110.0),
            cex_updated: Some(now),
            cex_ref_price: Some(100.0),
            cex_ref_instant: Some(now),
            pm_bid: Some(0.40),
            pm_ask: Some(0.42),
            pm_updated: Some(now),
        };
        // Large positive CEX return should push fair above mid enough for a signal.
        assert!(evaluate(&cfg, &s).is_some());
    }
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub fair: f64,
    pub mid: f64,
    pub edge: f64,
    pub cex_newer_than_pm: bool,
}

pub fn evaluate(cfg: &Config, s: &MarketState) -> Option<Signal> {
    let cex = s.cex_price?;
    let cex_t = s.cex_updated?;
    let ref_p = s.cex_ref_price?;
    let bid = s.pm_bid?;
    let ask = s.pm_ask?;
    let pm_t = s.pm_updated?;

    if cfg.only_when_cex_newer && cex_t <= pm_t {
        return None;
    }

    let now = Instant::now();
    if now.duration_since(pm_t) > cfg.max_book_staleness {
        return None;
    }
    if now.duration_since(cex_t) > cfg.max_cex_staleness {
        return None;
    }

    let mid = (bid + ask) * 0.5;
    let lr = (cex / ref_p).ln();
    if !lr.is_finite() || !mid.is_finite() {
        return None;
    }

    let fair = fair_up_probability(lr, cfg.k_return);
    let cex_newer_than_pm = cex_t > pm_t;
    let mut need = cfg.min_edge;
    if cex_newer_than_pm {
        need += cfg.lag_edge_boost;
    }

    let edge = fair - mid;
    if edge > need {
        Some(Signal {
            fair,
            mid,
            edge,
            cex_newer_than_pm,
        })
    } else {
        None
    }
}

pub async fn run_loop(
    cfg: Config,
    state: SharedState,
    mut live: Option<execution::LiveSession>,
) {
    let mut tick = interval(Duration::from_millis(50));
    let last_fire = Mutex::new(Option::<Instant>::None);

    if cfg.live && live.is_none() {
        warn!("live mode enabled but no authenticated CLOB session; no orders will be sent");
    }

    info!(
        live = cfg.live && live.is_some(),
        token = %cfg.yes_token_id,
        "lag-arb loop running (paper logs unless live session is active)"
    );

    loop {
        tick.tick().await;
        let snap = state.lock().clone();
        let Some(signal) = evaluate(&cfg, &snap) else {
            continue;
        };

        let mut gate = last_fire.lock();
        if let Some(t) = *gate {
            if t.elapsed() < cfg.cooldown {
                continue;
            }
        }
        *gate = Some(Instant::now());
        drop(gate);

        if cfg.live {
            if let Some(ref mut session) = live {
                let ask = snap.pm_ask.unwrap_or(signal.mid);
                match execution::market_buy_fok(session, &cfg, ask, signal.fair).await {
                    Ok(order_id) => info!(%order_id, "live FOK posted"),
                    Err(e) => warn!(error = %e, "order failed"),
                }
            }
        } else {
            info!(
                fair = signal.fair,
                mid = signal.mid,
                edge = signal.edge,
                cex_newer = signal.cex_newer_than_pm,
                "PAPER signal (set PM_ARB_LIVE=1 + private key for execution)"
            );
        }
    }
}
