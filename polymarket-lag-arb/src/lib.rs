//! Polymarket lag-arbitrage harness: compare fast CEX spot (RTDS) vs CLOB order book.
//!
//! This is research infrastructure, not a guaranteed profit system. Trading on
//! Polymarket may be restricted in your jurisdiction.

pub mod config;
pub mod engine;
pub mod execution;
pub mod feeds;
pub mod model;
pub mod price_cap;

pub use config::Config;
