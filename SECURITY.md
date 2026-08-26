# Security notes — TRatchet v0.3

This is a **lab / reference** implementation. It has not been independently reviewed. Treat findings below as open work, not as a claim of fitness.

## Threat model (intended)

- Two hosts, both online, want a session outside TLS.
- Hybrid: classical break or PQ break alone should not recover message keys.
- Forward secrecy per message; post-compromise security after a DH ratchet **and** a completed PQ epoch.
- Transport is untrusted except where the caller adds OS checks (Unix peer cred, TCP allowlists).

## Critical — must fix before any real deployment

### 1. Handshake is unauthenticated (MITM)

`createInit` / `respondInit` carry ephemeral X25519 and ML-KEM material with **no signature, no identity key, no TOFU pin**. An on-path attacker can run two sessions and decrypt both. PQXDH as used in Signal binds to **prekeys + identity**; this online variant does not.

**Fix:** long-term identity (Ed25519 or ML-DSA) signed into the handshake transcript, or TOFU of the first DH+KEM fingerprint with an out-of-band check.

### 2. Handshake records are not AEAD-protected

Init/resp are length-prefixed plaintext. Length and version are attacker-controlled until the first data record. A responder will run ML-KEM encapsulate on any well-formed init (CPU DoS).

**Fix:** cookie / retry-cookie, rate limit, and/or a signed/AAD transcript. Bind the handshake transcript into the first root KDF (already includes nonces + sid; add identity hashes).

### 3. `exportState` is JSON hex of live secrets

Root key, chain keys, DH secret, PQ chains are written as UTF-8 JSON. No wrapping key, no mlock, copies survive in V8 strings.

**Fix:** lab-only API, or encrypt-at-rest with a caller-supplied wrap key; never log.

## High

### 4. Unix bind is lab-unsafe

`node-host.ts` places a random name in the shared temp directory, default mode, no `SO_PEERCRED`. Name squatting / symlink races apply. See unix(7).

**Fix:** dedicated `0700` dir, `chmod 0600` after bind, unlink-before-bind, `SO_PEERCRED` allowlist.

### 5. Empty plaintext is overloaded as a control frame

The lab treats `pt.length === 0` as SPQR flush. A real app that sends empty payloads will be dropped from the chat and still consume ratchet steps. There is no header flag for control.

**Fix:** use the unused header `flags` byte (offset 1) for `CONTROL` / `SPQR-only`.

### 6. Skipped-key eviction is FIFO, not bound to DH

If `skipped.size > MAX_SKIPPED_STORE` (128), the **oldest map key** is dropped. An attacker who forces skips can invalidate legitimate delayed messages. `MAX_SKIP` is 64 per gap; combined with direction changes this is still a DoS/availability issue.

### 7. Message numbers are `u16`

`n` and `pn` wrap at 65536. There is no explicit rekey-before-wrap. A wrap without a DH ratchet reuses chain indices under a new chain only if a sending ratchet happened.

**Fix:** force a DH ratchet before wrap, or use `u32` / `u64`.

### 8. JavaScript cannot zeroize

`zeroize()` overwrites `Uint8Array` views. Engine copies, JIT, and GC replicas remain. Acceptable only for a prototype.

## Medium

### 9. No X25519 contributory check

`x25519.getSharedSecret` is used as-is. Small-order public keys can yield the all-zero shared secret. Noble may clamp; still reject all-zero DH output explicitly.

### 10. SPQR: single XOR parity, cleartext chunks

Chunks live in the **unencrypted** header (authenticated as AEAD AAD with the ciphertext). Drop-one recovery only. A drop of two chunks in an epoch stalls PQ PCS. Malicious modification fails AEAD (good). Metadata (epoch, indices) is visible.

### 11. SPQR ingest vs AEAD order

`decrypt` calls `pq.ingest(slots)` **before** AEAD success. Failed auth still advances sparse reconstruction state if header parsed. An attacker with a valid-looking header and garbage ct can poison chunk maps.

**Fix:** ingest SPQR only after `aeadOpen` succeeds (or buffer slots until then).

### 12. Root KDF shape differs from Signal

`kdfRk` uses `HKDF(ikm = rk ‖ dh, salt = empty)` rather than Signal’s usual `HKDF(ikm = dh, salt = rk)`. Domain-separated and not wrong by itself, but it is a compatibility/review hazard. Document or align.

### 13. No handshake replay cache

A captured init can be replayed to mint responder work and a new session the initiator never finishes. Pair with (2).

### 14. Hybrid nonce is HKDF-derived, not random

XChaCha20 nonce comes from `kdfHybrid`. Unique if hybrid MK is unique. If a bug reused a chain step, nonce reuse is immediate. XChaCha’s 192-bit nonce does not save a key reuse.

## Low / hygiene

- Header `flags` byte is always 0.
- `fingerprint` is SHA-256 truncated to 8 bytes — display only; do not use as a key id in a protocol.
- `skipId` uses that fingerprint; theoretical DH-pub collision in 64 bits (not practical).
- PQ epoch length (~20 frames) is a traffic-analysis signal on a quiet session.
- Same-process Node pair does not exercise `SO_PEERCRED` across uids.
- No formal spec for record MAX, version negotiation, or downgrade.

## What is in decent shape

- Hybrid IKM is `ec_mk ‖ pq_mk` with a distinct info string.
- Data records: AAD = `sid ‖ header` (chunks + DH pub bound to the ciphertext).
- Direction change triggers a sending DH ratchet.
- Length-prefixed streams; handshake sizes fixed.
- ML-KEM-768 via `@noble/post-quantum` (FIPS 203).
- Tests cover round-trip, out-of-order (2), DH ratchet, SPQR parity recovery, TCP and Unix pairs.

## Suggested next cuts (priority)

1. Identity signatures on the handshake transcript  
2. SPQR ingest after AEAD  
3. Control flag in header  
4. Reject zero DH secrets  
5. Unix `0700` + `SO_PEERCRED`  
6. Drop or wrap `exportState`  
7. u32 counters + forced ratchet before wrap
