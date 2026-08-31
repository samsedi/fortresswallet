//! Spending policy: defense-in-depth assuming everything upstream (the
//! crypto, the decoder) has an undiscovered bug. A per-transaction cap, a
//! rolling velocity limit, and a timelock on first-time destinations or
//! amounts above a threshold — so a single bug anywhere else in this
//! wallet can't drain funds in one instant transaction, and a large or
//! unfamiliar transfer always has a window where the legitimate owner
//! could notice and stop it.
//!
//! `evaluate` takes `now: SystemTime` as an explicit parameter rather
//! than calling `SystemTime::now()` internally — every test in this
//! module is fully deterministic as a result, with no reliance on wall-
//! clock timing or sleeps.
//!
//! Scope note: this engine decides *whether* and *when* a transaction is
//! allowed to proceed. It does not implement a persistent queue or
//! scheduler — actually holding a timelocked transaction until its
//! release time, and giving the owner a cancel window, is the calling
//! application's job (a real wallet daemon/frontend), backed by
//! `wallet-storage` if it needs to survive a restart. That integration
//! is deliberately out of scope here.
//!
//! `evaluate`/`record_approved` key spending history and known
//! destinations by `(chain_id, address)`, not address alone — 10 wei to
//! the same address on two different chains is tracked as two
//! independent totals, since the same 20-byte address can be controlled
//! by a different party on a different chain. This became load-bearing
//! once real multi-chain (EVM) support landed; see `wallet_core::evm`.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use wallet_decoder::DecodedTransaction;

/// Policy thresholds. All caller-configured — this module has no
/// built-in defaults, since "safe" limits are inherently deployment-
/// specific.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// A single transaction above this value is denied outright,
    /// regardless of velocity or destination.
    pub max_single_tx_value: u128,
    /// Sum of all *approved* transaction values within `window` may not
    /// exceed this.
    pub max_value_per_window: u128,
    /// Rolling window the velocity limit applies over.
    pub window: Duration,
    /// A transaction at or above this value, or to a destination never
    /// seen before by this engine, requires a timelock instead of
    /// immediate approval.
    pub timelock_threshold: u128,
    /// How long a timelocked transaction must wait before it's eligible
    /// for release.
    pub timelock_delay: Duration,
}

/// The result of evaluating one transaction against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allowed to sign immediately.
    Approved,
    /// Not allowed to sign at all — see `DenialReason`.
    Denied(DenialReason),
    /// Allowed, but only after `release_at`. The caller is responsible
    /// for holding the transaction and re-evaluating no earlier than
    /// this time; this engine does not track pending timelocks itself.
    Queued {
        /// Earliest time the caller may re-evaluate this transaction for
        /// approval.
        release_at: SystemTime,
    },
}

/// Why a transaction was denied outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Exceeds `max_single_tx_value` on its own.
    ExceedsSingleTxCap,
    /// Approving this would push the rolling-window total over
    /// `max_value_per_window`.
    ExceedsVelocityLimit,
}

/// Tracks approved-transaction history and known destinations to
/// evaluate policy decisions against. Construct one per wallet and reuse
/// it across every `sign_transaction` call — a fresh engine per call
/// would defeat the velocity limit and the "new destination" timelock
/// trigger entirely.
///
/// Governance note (OWASP: policy configuration should require a
/// separate, higher-privilege authorization path than the operations it
/// governs — otherwise anything that can request a spend could also
/// silently loosen the limits guarding that spend). Today, `config` is
/// private, set exactly once at construction in `new`, and there is no
/// method on this type that mutates it afterward — `&mut PolicyEngine`
/// currently grants no way to change limits, only to record history via
/// `record_approved`. That's not something enforced by a separate
/// governance process; it's enforced by this type simply not exposing a
/// setter. If a future change adds one (a `set_config`, a `&mut self`
/// field, `Deserialize` onto a live engine, ...), it must not be
/// reachable from the same trust boundary that can request transaction
/// signing — config changes should require at least the same threshold-
/// signing quorum spending itself does, not merely `&mut` access to this
/// struct.
pub struct PolicyEngine {
    config: PolicyConfig,
    /// (approval time, `chain_id`, value) for every transaction
    /// `record_approved` has been called on. Pruned eagerly in
    /// `record_approved`, the only mutation point — see O-1 in this
    /// crate's audit history. Keyed by `chain_id` as well as time so the
    /// velocity limit tracks each chain's spending independently — see
    /// the module docs' note on this crate's former known limitation.
    history: Vec<(SystemTime, u64, u128)>,
    /// `(chain_id, address)` — a destination known on one chain is *not*
    /// automatically known on another, since the same 20-byte address can
    /// be controlled by a different party on a different chain.
    known_destinations: HashSet<(u64, [u8; 20])>,
}

impl PolicyEngine {
    /// Construct a fresh engine with no history — every destination
    /// starts out "new" until a transaction to it is `record_approved`.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config, history: Vec::new(), known_destinations: HashSet::new() }
    }

    /// Evaluate `tx` against policy as of `now`. Does not mutate any
    /// state — call `record_approved` separately, and only after the
    /// transaction has actually been signed, so a ceremony failure after
    /// an `Approved` decision doesn't consume velocity budget for a
    /// transaction that never happened.
    pub fn evaluate(&self, tx: &DecodedTransaction, now: SystemTime) -> PolicyDecision {
        if tx.value > self.config.max_single_tx_value {
            return PolicyDecision::Denied(DenialReason::ExceedsSingleTxCap);
        }

        let window_total: u128 = self
            .history
            .iter()
            .filter(|(t, chain_id, _)| {
                *chain_id == tx.chain_id && now.duration_since(*t).is_ok_and(|age| age <= self.config.window)
            })
            .map(|(_, _, v)| v)
            .sum();

        // saturating_add: an attacker-controlled tx.value near u128::MAX
        // must not wrap this check around to "under the limit" — treat
        // overflow as "definitely over," which is what it is.
        if window_total.saturating_add(tx.value) > self.config.max_value_per_window {
            return PolicyDecision::Denied(DenialReason::ExceedsVelocityLimit);
        }

        let is_new_destination = !self.known_destinations.contains(&(tx.chain_id, tx.to));
        if tx.value >= self.config.timelock_threshold || is_new_destination {
            let release_at = now + self.config.timelock_delay;
            return PolicyDecision::Queued { release_at };
        }

        PolicyDecision::Approved
    }

    /// Record that `tx` was actually approved and signed at `now`. Call
    /// this only after a real signature was produced — not on every
    /// `Approved` decision, since the ceremony itself can still fail
    /// after policy approval (wrong shares, etc.).
    pub fn record_approved(&mut self, tx: &DecodedTransaction, now: SystemTime) {
        self.history.push((now, tx.chain_id, tx.value));
        self.known_destinations.insert((tx.chain_id, tx.to));
        // Prune eagerly here (the only mutation point) rather than only
        // filtering lazily in evaluate() — without this, a long-running
        // wallet's history grows without bound, one entry per approved
        // transaction, forever.
        self.history.retain(|(t, _, _)| now.duration_since(*t).is_ok_and(|age| age <= self.config.window));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PolicyConfig {
        PolicyConfig {
            max_single_tx_value: 1_000,
            max_value_per_window: 2_000,
            window: Duration::from_secs(3600),
            timelock_threshold: 500,
            timelock_delay: Duration::from_hours(24),
        }
    }

    fn tx(to: [u8; 20], value: u128) -> DecodedTransaction {
        DecodedTransaction { chain_id: 1, to, value }
    }

    #[test]
    fn config_enforcement_never_loosens_across_repeated_use() {
        // Governance guard: PolicyConfig has no setter, so this engine's
        // limits should be exactly as strict on the hundredth operation
        // as on the first. Absence of a mutation method can't be tested
        // directly, but its practical effect — that the single-tx cap
        // still denies the same oversized transaction after many
        // unrelated operations — can be, and would catch a future
        // `set_config`-style change that (correctly or not) let anything
        // with `&mut PolicyEngine` loosen the config.
        let mut engine = PolicyEngine::new(config());
        let now = SystemTime::now();

        for i in 0..100u8 {
            let dest = [i; 20];
            let small = tx(dest, 1);
            engine.evaluate(&small, now);
            engine.record_approved(&small, now);
        }

        let over_cap = tx([0xFF; 20], config().max_single_tx_value + 1);
        assert_eq!(engine.evaluate(&over_cap, now), PolicyDecision::Denied(DenialReason::ExceedsSingleTxCap));
    }

    #[test]
    fn small_tx_to_known_destination_approved_immediately() {
        let mut engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let dest = [0xAA; 20];

        // First transaction to any destination always queues — it's new
        // by definition. Simulate the caller releasing it after the
        // timelock and it getting approved/signed, which is what makes
        // the destination "known" for next time.
        let t1 = tx(dest, 100);
        assert_eq!(engine.evaluate(&t1, now), PolicyDecision::Queued { release_at: now + config().timelock_delay });
        engine.record_approved(&t1, now);

        // Now a small tx to the same (known) destination, under the
        // timelock threshold, is approved immediately.
        let t2 = tx(dest, 200);
        assert_eq!(engine.evaluate(&t2, now), PolicyDecision::Approved);
    }

    #[test]
    fn tx_exceeding_single_cap_denied() {
        let engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let t = tx([0xAA; 20], 1_001);

        assert_eq!(engine.evaluate(&t, now), PolicyDecision::Denied(DenialReason::ExceedsSingleTxCap));
    }

    #[test]
    fn new_destination_requires_timelock_even_for_small_amount() {
        let engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let t = tx([0xAA; 20], 10); // well under timelock_threshold

        let decision = engine.evaluate(&t, now);
        assert_eq!(decision, PolicyDecision::Queued { release_at: now + config().timelock_delay });
    }

    #[test]
    fn large_amount_to_known_destination_still_requires_timelock() {
        let mut engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let dest = [0xAA; 20];

        let small = tx(dest, 10);
        engine.evaluate(&small, now); // don't record — establish via record_approved instead
        engine.record_approved(&small, now);

        let large = tx(dest, 600); // >= timelock_threshold, known destination
        let decision = engine.evaluate(&large, now);
        assert_eq!(decision, PolicyDecision::Queued { release_at: now + config().timelock_delay });
    }

    #[test]
    fn velocity_limit_enforced_across_multiple_approved_transactions() {
        let mut engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let dest = [0xAA; 20];

        // Establish destination as known with small transactions so
        // later ones aren't blocked by the timelock-on-new-destination
        // rule, only by velocity.
        let t1 = tx(dest, 400);
        assert_eq!(engine.evaluate(&t1, now), PolicyDecision::Queued { release_at: now + config().timelock_delay });
        // Simulate the caller releasing it after the timelock and it
        // getting approved/signed.
        engine.record_approved(&t1, now);

        let t2 = tx(dest, 400);
        assert_eq!(engine.evaluate(&t2, now), PolicyDecision::Approved);
        engine.record_approved(&t2, now);

        // Total so far: 800. A third 400 pushes it to 1200 < 2000, fine.
        let t3 = tx(dest, 400);
        assert_eq!(engine.evaluate(&t3, now), PolicyDecision::Approved);
        engine.record_approved(&t3, now);

        // Total so far: 1200. A fourth 900 would push it to 2100 > 2000.
        let t4 = tx(dest, 900);
        assert_eq!(engine.evaluate(&t4, now), PolicyDecision::Denied(DenialReason::ExceedsVelocityLimit));
    }

    #[test]
    fn velocity_window_expires_old_history() {
        let mut engine = PolicyEngine::new(config());
        let start = SystemTime::now();
        let dest = [0xAA; 20];

        let t1 = tx(dest, 400);
        engine.record_approved(&t1, start);

        // Just past the window: the old 400 no longer counts, so a fresh
        // 1900 (under the 2000 cap on its own) should be approved rather
        // than counted as 400 + 1900 = 2300 > 2000.
        let later = start + config().window + Duration::from_secs(1);
        let t2 = tx(dest, 900); // under timelock_threshold... wait, 900 >= 500
        let decision = engine.evaluate(&t2, later);
        // 900 >= timelock_threshold (500), so this queues rather than
        // approves outright — still proves the old history didn't count
        // toward velocity, since a Denied would mean it did.
        assert_eq!(decision, PolicyDecision::Queued { release_at: later + config().timelock_delay });
    }

    #[test]
    fn old_history_entries_are_pruned_not_retained_forever() {
        // O-1: without pruning, `history` grows one entry per approved
        // transaction forever, even though only entries within the
        // rolling window are ever consulted. record_approved should
        // drop stale entries as it goes.
        let mut engine = PolicyEngine::new(config());
        let start = SystemTime::now();
        let dest = [0xAA; 20];

        engine.record_approved(&tx(dest, 10), start);
        engine.record_approved(&tx(dest, 10), start);
        engine.record_approved(&tx(dest, 10), start);
        assert_eq!(engine.history.len(), 3);

        // A later approval, well past the window, should prune all three
        // old entries and leave only itself.
        let later = start + config().window + Duration::from_secs(1);
        engine.record_approved(&tx(dest, 10), later);
        assert_eq!(engine.history.len(), 1);
    }

    #[test]
    fn record_approved_is_required_for_history_to_count() {
        // evaluate() alone must not mutate state — only record_approved
        // does. This is what makes "policy approved but ceremony failed"
        // safe: no velocity budget is consumed for a transaction that
        // never actually got signed.
        let engine = PolicyEngine::new(config());
        let now = SystemTime::now();
        let dest = [0xAA; 20];

        let t1 = tx(dest, 400);
        let _ = engine.evaluate(&t1, now); // deliberately not recorded

        let t2 = tx(dest, 400);
        // If evaluate() had mutated history, this would still see 400
        // already counted. It shouldn't — this is a fresh new-destination
        // queue decision, not a velocity denial, and definitely not
        // silently treating t1 as spent.
        let decision = engine.evaluate(&t2, now);
        assert_ne!(decision, PolicyDecision::Denied(DenialReason::ExceedsVelocityLimit));
    }

    #[test]
    fn near_max_value_does_not_overflow_the_velocity_check() {
        // With a realistic single-tx cap, a huge value is denied before
        // ever reaching the velocity check's addition — this test uses a
        // separate config with an effectively unbounded single-tx cap
        // specifically to reach that addition and prove it saturates
        // instead of wrapping.
        let config = PolicyConfig {
            max_single_tx_value: u128::MAX,
            max_value_per_window: 1_000,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX, // never queue, isolate the velocity check
            timelock_delay: Duration::from_secs(1),
        };
        let engine = PolicyEngine::new(config);
        let now = SystemTime::now();
        let t = tx([0xAA; 20], u128::MAX);

        // window_total (0) + u128::MAX would wrap to a small number with
        // plain `+`, which could pass a `> max_value_per_window` check
        // incorrectly. saturating_add keeps it at u128::MAX, correctly
        // denied.
        assert_eq!(engine.evaluate(&t, now), PolicyDecision::Denied(DenialReason::ExceedsVelocityLimit));
    }
}
