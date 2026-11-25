//! Live order path using Polymarket's official Rust CLOB client (`polymarket-client-sdk`).
//!
//! Signing uses Alloy's [`LocalSigner`] (Polygon chain id), matching Polymarket docs.

use std::str::FromStr as _;

use alloy::signers::Signer as _;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use polymarket_client_sdk::auth::Normal;
use polymarket_client_sdk::auth::state::Authenticated;
use polymarket_client_sdk::clob::types::{Amount, OrderType, Side};
use polymarket_client_sdk::clob::{Client as ClobClient, Config as ClobConfig};
use polymarket_client_sdk::types::Decimal;
use polymarket_client_sdk::types::U256;
use polymarket_client_sdk::{POLYGON, PRIVATE_KEY_VAR};

use crate::config::Config;
use crate::price_cap::compute_fok_buy_price;

pub type AuthClob = ClobClient<Authenticated<Normal>>;

pub struct LiveSession {
    pub client: AuthClob,
    pub signer: PrivateKeySigner,
}

pub async fn connect() -> Result<LiveSession> {
    let private_key = std::env::var(PRIVATE_KEY_VAR)
        .with_context(|| format!("{PRIVATE_KEY_VAR} must be set for live trading"))?;
    let signer = PrivateKeySigner::from_str(&private_key)
        .context("parse private key")?
        .with_chain_id(Some(POLYGON));
    let client = ClobClient::new("https://clob.polymarket.com", ClobConfig::default())
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .authentication_builder(&signer)
        .authenticate()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(LiveSession { client, signer })
}

fn decimal_from_f64(x: f64) -> Result<Decimal> {
    Decimal::from_f64_retain(x).ok_or_else(|| anyhow::anyhow!("invalid decimal"))
}

pub async fn market_buy_fok(
    session: &mut LiveSession,
    cfg: &Config,
    ask: f64,
    fair: f64,
) -> Result<String> {
    let token_id: U256 = cfg
        .yes_token_id
        .parse()
        .map_err(|e| anyhow::anyhow!("token id: {e}"))?;
    let usdc = Amount::usdc(decimal_from_f64(cfg.order_usdc)?).map_err(|e| anyhow::anyhow!("{e}"))?;
    let worst = decimal_from_f64(compute_fok_buy_price(cfg, ask, fair)?)?;

    let order = session
        .client
        .market_order()
        .token_id(token_id)
        .amount(usdc)
        .side(Side::Buy)
        .order_type(OrderType::FOK)
        .price(worst)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let signed = session
        .client
        .sign(&session.signer, order)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let response = session
        .client
        .post_order(signed)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(response.order_id.to_string())
}
