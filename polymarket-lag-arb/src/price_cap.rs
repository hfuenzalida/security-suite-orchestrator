//! Bound live FOK buy prices to the current book and modeled fair value.

use anyhow::{bail, Result};

use crate::config::Config;

/// Compute the max buy price for a FOK order at submit time.
///
/// Caps at the tightest of:
/// - configured hard ceiling (`worst_price_slippage`)
/// - current ask + allowed absolute slippage
/// - fair value minus minimum edge (do not pay away the signal)
///
/// Aborts when the ask has moved beyond that bound.
pub fn compute_fok_buy_price(cfg: &Config, ask: f64, fair: f64) -> Result<f64> {
    if !ask.is_finite() || ask <= 0.0 || ask >= 1.0 {
        bail!("invalid ask for execution: {ask}");
    }
    if !fair.is_finite() || fair <= 0.0 || fair >= 1.0 {
        bail!("invalid fair for execution: {fair}");
    }

    let edge_cap = fair - cfg.min_edge;
    let book_cap = ask + cfg.max_ask_slippage;
    let price = cfg
        .worst_price_slippage
        .min(edge_cap)
        .min(book_cap)
        .clamp(0.01, 0.99);

    if price + 1e-9 < ask {
        bail!(
            "execution aborted: ask {ask} exceeds bounded cap {price} (fair={fair}, min_edge={})",
            cfg.min_edge
        );
    }
    Ok(price)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg() -> Config {
        Config {
            yes_token_id: "1".into(),
            cex_symbol: "btcusdt".into(),
            min_edge: 0.03,
            k_return: 12.0,
            max_book_staleness: Duration::from_millis(750),
            max_cex_staleness: Duration::from_millis(2000),
            lag_edge_boost: 0.01,
            order_usdc: 5.0,
            worst_price_slippage: 0.99,
            max_ask_slippage: 0.02,
            cooldown: Duration::from_millis(1500),
            ref_horizon: Duration::from_millis(2000),
            only_when_cex_newer: false,
            live: false,
        }
    }

    #[test]
    fn caps_below_static_worst_using_ask_and_fair() {
        let c = cfg();
        // fair=0.60, min_edge=0.03 => edge_cap=0.57; ask=0.50 => book_cap=0.52
        let p = compute_fok_buy_price(&c, 0.50, 0.60).unwrap();
        assert!((p - 0.52).abs() < 1e-9);
        assert!(p < c.worst_price_slippage);
    }

    #[test]
    fn aborts_when_ask_blows_through_edge() {
        let c = cfg();
        // ask=0.58, fair=0.60, min_edge=0.03 => edge_cap=0.57 < ask
        let err = compute_fok_buy_price(&c, 0.58, 0.60).unwrap_err();
        assert!(format!("{err}").contains("aborted"));
    }
}
