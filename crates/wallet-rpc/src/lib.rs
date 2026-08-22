//! Chain queries: balance, nonce, gas price, confirmation status.
//!
//! Treat every response as untrusted — a malicious or MITM'd node can lie.
//! Cross-check against multiple independent RPC endpoints for anything
//! funds-critical before wallet-core acts on it. This crate must never
//! depend on `wallet-crypto`; it has no business touching key material.
//!
//! Rules for this crate:
//!
//! 1. Every public type returned by an RPC query must be wrapped in
//!    `Untrusted<T>` — callers cannot use the inner value without
//!    explicitly calling `.trust()` or `.cross_check()`.
//!
//! 2. For funds-critical queries (balance, nonce), prefer `cross_check`
//!    over `trust`: it queries multiple independent nodes and fails if
//!    they disagree, rather than acting on one node's word alone.
//!
//! 3. Once this crate has a real network client (Phase 7), all
//!    HTTP/JSON-RPC calls it makes must have:
//!      - size limits (no unbounded reads)
//!      - timeouts (no hanging on a stalled node)
//!      - TLS certificate pinning (no MITM)
//!
//! `cross_check` below is deliberately synchronous and takes its query
//! function as a parameter for now — there is no real client yet to make
//! it worth being `async`. It should become `async fn` calling an actual
//! HTTP/JSON-RPC client once one exists.

/// A chain RPC endpoint. Just an identifier for now — no connection state
/// until a real network client lands in Phase 7.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint(pub String);

/// Wrapper that forces callers to explicitly acknowledge they're acting
/// on unverified data from a single RPC node, rather than letting a raw
/// `Balance`/`Nonce`/etc. flow straight into a spending decision.
#[derive(Debug, Clone)]
pub struct Untrusted<T> {
    value: T,
    source: Endpoint,
}

impl<T> Untrusted<T> {
    /// Wrap a value with the endpoint it came from.
    pub fn new(value: T, source: Endpoint) -> Self {
        Self { value, source }
    }

    /// Which endpoint this value came from.
    pub fn source(&self) -> &Endpoint {
        &self.source
    }

    /// "I understand this came from one node and might be a lie." Use
    /// only for non-funds-critical data; prefer `cross_check` otherwise.
    pub fn trust(self) -> T {
        self.value
    }
}

impl<T: Clone + PartialEq> Untrusted<T> {
    /// Re-run the same query against `others`; succeed only if every
    /// response matches this value. Returns the first disagreement found,
    /// naming both endpoints involved, rather than picking a "winner".
    pub fn cross_check(
        self,
        others: &[Endpoint],
        query: impl Fn(&Endpoint) -> T,
    ) -> Result<T, RpcDisagreement> {
        for endpoint in others {
            if query(endpoint) != self.value {
                return Err(RpcDisagreement {
                    primary: self.source.clone(),
                    disagreeing: endpoint.clone(),
                });
            }
        }
        Ok(self.value)
    }
}

/// Two RPC endpoints returned different answers for the same
/// funds-critical query — at least one of them is lying or stale.
#[derive(Debug)]
pub struct RpcDisagreement {
    /// The endpoint the original `Untrusted<T>` value came from.
    pub primary: Endpoint,
    /// The endpoint whose response didn't match.
    pub disagreeing: Endpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(name: &str) -> Endpoint {
        Endpoint(name.to_string())
    }

    #[test]
    fn trust_returns_inner_value_unconditionally() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        assert_eq!(balance.trust(), 100);
    }

    #[test]
    fn cross_check_succeeds_when_all_endpoints_agree() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let others = [endpoint("node-b"), endpoint("node-c")];

        let result = balance.cross_check(&others, |_| 100u64);
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn cross_check_fails_on_first_disagreement() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let others = [endpoint("node-b"), endpoint("node-c")];

        // node-b lies about the balance.
        let result = balance.cross_check(&others, |e| if e.0 == "node-b" { 999 } else { 100 });

        let err = result.unwrap_err();
        assert_eq!(err.primary, endpoint("node-a"));
        assert_eq!(err.disagreeing, endpoint("node-b"));
    }

    #[test]
    fn cross_check_with_no_other_endpoints_trusts_the_lone_value() {
        // Degenerate case: nothing to cross-check against. This is a
        // config problem (only one RPC endpoint configured), not
        // something this type can catch — documented, not silently hidden.
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let result = balance.cross_check(&[], |_| unreachable!("no other endpoints to query"));
        assert_eq!(result.unwrap(), 100);
    }
}
