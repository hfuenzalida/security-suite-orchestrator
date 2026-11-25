//! Lightweight fair-value mapping from short-horizon CEX returns.
//!
//! This is intentionally small: production systems replace this with a calibrated
//! model that conditions on time-to-expiry, strike, funding, and microstructure.

/// Map a log return over the observation horizon to a subjective probability of "Up".
///
/// Uses a logistic squashing so huge moves saturate near 0/1 instead of blowing up.
#[must_use]
pub fn fair_up_probability(log_return: f64, k: f64) -> f64 {
    let x = (k * log_return).clamp(-8.0, 8.0);
    let p = 1.0 / (1.0 + (-x).exp());
    p.clamp(0.01, 0.99)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_return_is_half() {
        let p = fair_up_probability(0.0, 12.0);
        assert!((p - 0.5).abs() < 1e-9);
    }
}
