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

Root key, chain keys, DH secret, PQ chains are written as UTF-8 JSON. No wrapping key, no mlock, copies survive in V8 strings. `importState` also omits skipped keys, in-flight SPQR chunks, and `offerSk`.

**Fix:** lab-only API, or encrypt-at-rest with a caller-supplied wrap key; never log.

## High

### 4. Unix bind is still lab-grade

`node-host.ts` now uses `mkdtemp` + `chmod 0700` on the directory and `chmod 0600` on the socket. It still lives under the shared temp directory, still has no `SO_PEERCRED` allowlist, and still does not use the abstract namespace. Name squatting on the parent `/tmp` is reduced, not eliminated.

**Fix:** dedicated `0700` dir outside world-writable parents, `SO_PEERCRED` uid allowlist, unlink-before-bind.

### 5. Empty plaintext is overloaded as a control frame

The lab treats `pt.length === 0` as SPQR flush. A real app that sends empty payloads will be dropped from the chat and still consume ratchet steps. There is no header flag for control.

**Fix:** use the unused header `flags` byte (offset 1) for `CONTROL` / `SPQR-only`.

### 6. Skipped-key eviction is FIFO, not bound to DH

If `skipped.size > MAX_SKIPPED_STORE` (128), the **oldest map key** is dropped. An attacker who forces skips can invalidate legitimate delayed messages. `MAX_SKIP` is 64 per gap; combined with direction changes this is still a DoS/availability issue.

### 7. Message numbers are `u16`

`n` and `pn` wrap at 65536. Encrypt now forces a DH ratchet before the counter exceeds `0xffff`. That is a local mitigation; the wire type is still 16-bit.

### 8. JavaScript cannot zeroize

`zeroize()` overwrites `Uint8Array` views. Engine copies, JIT, and GC replicas remain. Acceptable only for a prototype.

## Medium

### 9. X25519 contributory check — mitigated

`dhShared` now rejects all-zero shared secrets and maps Noble's invalid-key errors to `TR_DH_WEAK`. Small-order points Noble already rejects stay rejected.

### 10. SPQR: single XOR parity, cleartext chunks

Chunks live in the **unencrypted** header (authenticated as AEAD AAD with the ciphertext). Drop-one recovery only. A drop of two chunks in an epoch stalls PQ PCS. Malicious modification fails AEAD (good). Metadata (epoch, indices) is visible.

### 11. SPQR ingest vs AEAD order — mitigated

`decrypt` used to call `pq.ingest(slots)` **before** AEAD success. Failed auth still advanced sparse reconstruction. Ingest now runs only after `aeadOpen` succeeds. Failed records also restore Double Ratchet / skip-store snapshots so a garbage header cannot desync the session.

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
- `installEpoch` is a `u8` while SPQR epoch is `u16` — install flag wraps at 256.
- Handshake IKM does not include raw public keys as an extra transcript hash (DH/KEM shared secrets bind them, identity still missing).
- `RecordParser` concatenates into a growing buffer; bounded by `MAX_RECORD` per frame, not by total connection lifetime.
- Lab snapshot fingerprints leak chain-key prefixes into the UI.

## Mitigated in-tree (see `session.adversarial.test.ts`)

- Failed AEAD no longer commits ratchet / SPQR / skip-store state.
- Replay of a delivered `(dhPub, n)` throws `TR_REPLAY` without advancing.
- Tampered DH pub in an otherwise well-formed header is rolled back.
- Out-of-order skip keys are not dropped until AEAD succeeds.
- All-zero / rejected X25519 publics throw `TR_DH_WEAK`.
- `fromHex` rejects non-hex rather than silently writing `NaN → 0`.

## What is in decent shape

- Hybrid IKM is `ec_mk ‖ pq_mk` with a distinct info string.
- Data records: AAD = `sid ‖ header` (chunks + DH pub bound to the ciphertext).
- Direction change triggers a sending DH ratchet.
- Length-prefixed streams; handshake sizes fixed.
- ML-KEM-768 via `@noble/post-quantum` (FIPS 203).
- Tests cover round-trip, out-of-order (2), DH ratchet, SPQR parity recovery, TCP and Unix pairs, plus adversarial rollback.

## Suggested next cuts (priority)

1. Identity signatures on the handshake transcript  
2. Control flag in header  
3. Unix `SO_PEERCRED` + non-tmp bind  
4. Drop or wrap `exportState`  
5. Handshake cookies / rate-limit  
6. u32 counters on the wire  
7. Bind handshake public keys + identity into the root KDF transcript
