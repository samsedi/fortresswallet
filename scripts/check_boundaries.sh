#!/usr/bin/env bash
# Fails the build if a crate gains a dependency edge that breaks the
# workspace's blast-radius architecture (see Cargo.toml comments on each
# crate for the intended trust boundaries).
set -euo pipefail

fail=0

# wallet-decoder must NEVER depend on wallet-crypto (no key material access)
if cargo tree -p wallet-decoder 2>/dev/null | grep -q "wallet-crypto"; then
    echo "❌ BOUNDARY VIOLATION: wallet-decoder depends on wallet-crypto"
    echo "   The decoder must never have access to key material."
    fail=1
fi

# wallet-rpc must NEVER depend on wallet-crypto (no key material access)
if cargo tree -p wallet-rpc 2>/dev/null | grep -q "wallet-crypto"; then
    echo "❌ BOUNDARY VIOLATION: wallet-rpc depends on wallet-crypto"
    echo "   The RPC layer must never have access to key material."
    fail=1
fi

# wallet-cli must NOT directly depend on wallet-crypto or wallet-storage
# (it should go through wallet-core only)
if grep -q 'wallet-crypto' crates/wallet-cli/Cargo.toml; then
    echo "❌ BOUNDARY VIOLATION: wallet-cli directly depends on wallet-crypto"
    echo "   CLI should access crypto only through wallet-core."
    fail=1
fi

if grep -q 'wallet-storage' crates/wallet-cli/Cargo.toml; then
    echo "❌ BOUNDARY VIOLATION: wallet-cli directly depends on wallet-storage"
    echo "   CLI should access storage only through wallet-core."
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "✅ All dependency boundaries respected."
fi

exit "$fail"
