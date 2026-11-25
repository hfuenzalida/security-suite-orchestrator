use std::time::Duration;

use anyhow::{bail, Context, Result};

/// Runtime knobs (env-driven so hot-reload / containers stay simple).
#[derive(Debug, Clone)]
pub struct Config {
    /// Outcome token id for the YES leg (CLOB `asset_id` / `token_id` decimal string).
    pub yes_token_id: String,
    pub cex_symbol: String,
    /// Minimum edge (fair minus Polymarket mid) required before firing.
    pub min_edge: f64,
    /// Scale factor mapping short-horizon CEX return → probability shift.
    pub k_return: f64,
    /// Ignore signals if Polymarket book is older than this.
    pub max_book_staleness: Duration,
    /// Ignore signals if CEX/RTDS price is older than this.
    pub max_cex_staleness: Duration,
    /// Extra edge required when the book is stale vs CEX (lag premium).
    pub lag_edge_boost: f64,
    pub order_usdc: f64,
    /// Absolute hard ceiling for FOK buy price (0..1).
    pub worst_price_slippage: f64,
    /// Max absolute price above best ask allowed at submit time.
    pub max_ask_slippage: f64,
    pub cooldown: Duration,
    /// Rolling reference horizon for CEX log-returns (RTDS updates reference price).
    pub ref_horizon: Duration,
    /// If true, only evaluate when the latest CEX tick is newer than the last PM book update.
    pub only_when_cex_newer: bool,
    pub live: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let yes_token_id = std::env::var("POLYMARKET_YES_TOKEN_ID")
            .context("POLYMARKET_YES_TOKEN_ID is required (decimal string from the Polymarket UI)")?;

        let cex_symbol = std::env::var("PM_ARB_CEX_SYMBOL").unwrap_or_else(|_| "btcusdt".to_owned());

        let min_edge = parse_env_f64("PM_ARB_MIN_EDGE", 0.03)?;
        let k_return = parse_env_f64("PM_ARB_K_RETURN", 12.0)?;
        let max_book_ms = parse_env_f64("PM_ARB_MAX_BOOK_STALE_MS", 750.0)?;
        let max_cex_ms = parse_env_f64("PM_ARB_MAX_CEX_STALE_MS", 2000.0)?;
        let lag_edge_boost = parse_env_f64("PM_ARB_LAG_EDGE_BOOST", 0.01)?;
        let order_usdc = parse_env_f64("PM_ARB_ORDER_USDC", 5.0)?;
        let worst_price_slippage = parse_env_f64("PM_ARB_WORST_PRICE", 0.99)?;
        let max_ask_slippage = parse_env_f64("PM_ARB_MAX_ASK_SLIP", 0.02)?;
        let cooldown_ms = parse_env_f64("PM_ARB_COOLDOWN_MS", 1500.0)?;
        let ref_horizon_ms = parse_env_f64("PM_ARB_REF_HORIZON_MS", 2000.0)?;
        let only_when_cex_newer = std::env::var("PM_ARB_ONLY_WHEN_CEX_NEWER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let live = std::env::var("PM_ARB_LIVE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(Self {
            yes_token_id,
            cex_symbol,
            min_edge,
            k_return,
            max_book_staleness: duration_from_ms(max_book_ms, "PM_ARB_MAX_BOOK_STALE_MS")?,
            max_cex_staleness: duration_from_ms(max_cex_ms, "PM_ARB_MAX_CEX_STALE_MS")?,
            lag_edge_boost,
            order_usdc,
            worst_price_slippage,
            max_ask_slippage,
            cooldown: duration_from_ms(cooldown_ms, "PM_ARB_COOLDOWN_MS")?,
            ref_horizon: duration_from_ms(ref_horizon_ms, "PM_ARB_REF_HORIZON_MS")?,
            only_when_cex_newer,
            live,
        })
    }
}

fn duration_from_ms(ms: f64, key: &str) -> Result<Duration> {
    if !ms.is_finite() || ms < 0.0 {
        bail!("invalid duration ms for {key}: {ms}");
    }
    // Prefer try_from to avoid panics on overflow / non-finite edge cases.
    Duration::try_from_secs_f64(ms / 1000.0).map_err(|e| {
        anyhow::anyhow!("invalid duration ms for {key}: {ms} ({e})")
    })
}

fn parse_env_f64(key: &str, default: f64) -> Result<f64> {
    match std::env::var(key) {
        Ok(v) => {
            let n = v
                .parse::<f64>()
                .with_context(|| format!("invalid float for {key}"))?;
            if !n.is_finite() {
                bail!("non-finite float for {key}");
            }
            Ok(n)
        }
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_from_ms_rejects_negative() {
        assert!(duration_from_ms(-1.0, "X").is_err());
    }

    #[test]
    fn duration_from_ms_rejects_nan() {
        assert!(duration_from_ms(f64::NAN, "X").is_err());
    }

    #[test]
    fn duration_from_ms_rejects_infinity() {
        assert!(duration_from_ms(f64::INFINITY, "X").is_err());
    }

    #[test]
    fn duration_from_ms_accepts_zero_and_positive() {
        assert_eq!(duration_from_ms(0.0, "X").unwrap(), Duration::from_millis(0));
        assert_eq!(duration_from_ms(1500.0, "X").unwrap(), Duration::from_millis(1500));
    }

    #[test]
    fn parse_env_f64_rejects_non_finite() {
        let key = "PM_ARB_TEST_NONFINITE_MS";
        std::env::set_var(key, "nan");
        let err = parse_env_f64(key, 1.0);
        std::env::remove_var(key);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("non-finite") || msg.contains("invalid"), "{msg}");
    }
}
