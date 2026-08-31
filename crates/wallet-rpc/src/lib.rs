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
//! function as a parameter — this crate's real client (`evm::JsonRpcClient`)
//! is itself blocking/synchronous, not `async`, matching the rest of this
//! workspace: nothing else here is async, and a CLI wallet has no
//! throughput requirement that would justify pulling an async runtime
//! through `wallet-core`/`wallet-cli`.

pub mod evm;

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

    /// Like `cross_check`, but for a real network query that can itself
    /// fail (connection refused, timeout, malformed response, ...) rather
    /// than the infallible `Fn(&Endpoint) -> T` `cross_check` assumes.
    /// `evm::JsonRpcClient`'s methods are all fallible, so this is the
    /// variant real callers use; `cross_check` stays as-is for callers
    /// (and tests) where the query genuinely cannot fail.
    pub fn try_cross_check<E>(self, others: &[Endpoint], query: impl Fn(&Endpoint) -> Result<T, E>) -> Result<T, CrossCheckError<E>> {
        for endpoint in others {
            let value = query(endpoint).map_err(|e| CrossCheckError::Query(endpoint.clone(), e))?;
            if value != self.value {
                return Err(CrossCheckError::Disagreement(RpcDisagreement {
                    primary: self.source.clone(),
                    disagreeing: endpoint.clone(),
                }));
            }
        }
        Ok(self.value)
    }
}

/// Errors from `Untrusted::try_cross_check`: either a secondary
/// endpoint's query itself failed, or it succeeded but disagreed with
/// the primary value.
#[derive(Debug)]
pub enum CrossCheckError<E> {
    /// Querying `.0` for the same value failed with `.1` — this is not
    /// evidence of disagreement, just an unreachable/erroring endpoint,
    /// but it still means the value could not be corroborated.
    Query(Endpoint, E),
    /// Two endpoints returned different answers — see `RpcDisagreement`.
    Disagreement(RpcDisagreement),
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
    fn try_cross_check_succeeds_when_all_endpoints_agree() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let others = [endpoint("node-b"), endpoint("node-c")];

        let result = balance.try_cross_check::<()>(&others, |_| Ok(100u64));
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn try_cross_check_reports_disagreement_distinct_from_query_failure() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let others = [endpoint("node-b")];

        let result = balance.try_cross_check::<()>(&others, |_| Ok(999u64));
        assert!(matches!(result, Err(CrossCheckError::Disagreement(_))));
    }

    #[test]
    fn try_cross_check_reports_query_failure_distinct_from_disagreement() {
        let balance = Untrusted::new(100u64, endpoint("node-a"));
        let others = [endpoint("node-b")];

        let result = balance.try_cross_check(&others, |_| Err::<u64, &str>("connection refused"));
        assert!(matches!(result, Err(CrossCheckError::Query(_, "connection refused"))));
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
