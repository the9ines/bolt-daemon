//! Monotonic request ID generation for IPC correlation.

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique request ID: `evt-<monotonic counter>`.
pub fn generate_request_id() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("evt-{n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_matches_expected_pattern() {
        let id = generate_request_id();
        assert!(id.starts_with("evt-"), "expected evt- prefix, got: {id}");
        let suffix = &id["evt-".len()..];
        assert!(
            suffix.parse::<u64>().is_ok(),
            "suffix not numeric: {suffix}"
        );
    }

    #[test]
    fn sequential_ids_are_unique() {
        let a = generate_request_id();
        let b = generate_request_id();
        let c = generate_request_id();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn counter_is_monotonically_increasing() {
        let parse = |id: &str| -> u64 { id["evt-".len()..].parse().unwrap() };
        let a = generate_request_id();
        let b = generate_request_id();
        let c = generate_request_id();
        assert!(parse(&b) > parse(&a));
        assert!(parse(&c) > parse(&b));
    }
}
