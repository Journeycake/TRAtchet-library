# Target Specification: Custom Transport Protocol (TRAtchet)
## Online PQXDH-Style Handshake + Triple Ratchet
**Document Type:** Build / Implementation Target Spec  
**Version:** 0.3  
**Status:** Draft for Build Session  
**Date:** 2026-08-25  
**Previous:** v0.2 (online PQXDH + multiple SCKA options)  
**Related Document:** `Custom_Transport_Protocol_Triple_Ratchet_Overview.pdf`

---

## 1. Purpose

Build a portable cryptographic library that provides:

- Host-to-host encrypted communication **outside** TLS, IPsec, WireGuard, or other existing transport security protocols.
- Per-message unique encryption keys derived from a continuous hybrid ratchet.
- Hybrid classical + post-quantum security.
- Self-healing (forward secrecy + post-compromise security).
- Clean importability into Ubuntu, RHEL/Rocky/Alma, and macOS clients via C ABI.

The library itself performs **no network I/O**. Callers supply the transport (UDP, raw sockets, TCP streams, etc.).

---

## 2. Goals & Non-Goals

### Goals
- **Online PQXDH-style initial key exchange** (both hosts must be online and able to exchange messages interactively).
- Triple Ratchet (Double Ratchet + Sparse Post-Quantum Ratchet / SPQR) for ongoing per-message key derivation.
- Hybrid message key = `KDF_HYBRID(classical_mk ‖ pq_mk)`.
- Self-healing: compromise of any single message key or intermediate state does not permanently break the session.
- C ABI suitable for linking from C, C++, Go, Python, Rust, etc.
- Packaging: `.deb`, `.rpm`, Homebrew formula.

### Non-Goals (v0.2)
- Offline / asynchronous pre-key bundles (recipient **must** be online).
- Integration with existing TLS or WireGuard stacks.
- Formal verification or third-party audit (planned for later phase).
- High-level application protocol (messaging, file transfer, etc.).

---

## 3. Trust & Handshake Model (Updated)

### 3.1 Online Requirement

**The recipient host MUST be online and responsive for the initial key exchange.**  
There is no support for leaving pre-key material that allows a fully offline handshake. Both parties exchange ephemeral classical and post-quantum public values in real time.

This simplifies the threat model (no long-lived pre-key compromise window) at the cost of requiring simultaneous availability.

### 3.2 PQXDH-Style Initial Exchange

The initial shared secret is established with a **PQXDH-style** handshake:

1. Both parties generate ephemeral X25519 key pairs.
2. Both parties generate ephemeral ML-KEM key pairs (or one side encapsulates to the other’s static/ephemeral ML-KEM key).
3. Classical Diffie-Hellman shared secrets and ML-KEM shared secrets are combined via a hybrid KDF to produce the root shared secret.
4. The resulting shared secret is fed into Triple Ratchet initialization (exactly as a classic X3DH/PQXDH output would be).

Identity binding (optional but recommended) can be added later via long-term identity keys or certificates; the core v0.2 design focuses on the online ephemeral exchange.

### 3.3 Comparison to Previous OpenPGP Model

| Aspect                    | v0.1 (OpenPGP)              | v0.2 (PQXDH-style)              |
|---------------------------|-----------------------------|---------------------------------|
| Recipient availability    | Offline possible            | **Must be online**              |
| Initial secret protection | OpenPGP public-key encrypt  | Interactive hybrid KEM + DH     |
| Quantum resistance of handshake | Depends on OpenPGP algorithms | Explicit ML-KEM                 |
| Pre-shared material       | Long-lived OpenPGP key      | None required for basic mode    |

---

## 4. Protocol Phases

### Phase 1 – Online PQXDH-Style Handshake (both hosts online)

1. Initiator sends: ephemeral X25519 public key + ephemeral ML-KEM public key (or encapsulation key) + nonce.
2. Responder replies: ephemeral X25519 public key + ML-KEM ciphertext (or its own public key) + nonce.
3. Both sides compute the hybrid shared secret:
   - Classical DH output(s)
   - ML-KEM shared secret
   - Combined via HKDF with domain separation.
4. The shared secret initializes the Triple Ratchet state on both sides.

### Phase 2 – Steady-State Messaging (Triple Ratchet)

For every application message:

1. Advance classical Double Ratchet → `ec_mk` + header material.
2. Advance SPQR → `pq_mk` + header material (chunked / erasure-coded).
3. `final_mk = KDF_HYBRID(ec_mk, pq_mk)`.
4. AEAD-encrypt payload under `final_mk` (XChaCha20-Poly1305 or AES-256-GCM recommended).
5. Authenticate combined ratchet headers as AAD.

---

## 5. Cryptographic Requirements

| Component                  | Primitive / Construction                          | Notes |
|----------------------------|---------------------------------------------------|-------|
| Initial Handshake          | PQXDH-style (X25519 + ML-KEM)                     | Both parties online |
| Classical Ratchet          | X25519 Diffie-Hellman + symmetric KDF chain       | Signal Double Ratchet |
| Post-Quantum Ratchet       | SPQR (ML-KEM based continuous key agreement)      | Sparse / chunked |
| Hybrid Combination         | `KDF_HYBRID(ec_mk ‖ pq_mk)`                       | Must require both |
| Message Encryption         | XChaCha20-Poly1305 or AES-256-GCM                 | AEAD with header as AAD |
| Key Derivation             | HKDF-SHA256 / SHA-512                             | Domain-separated labels |

**Decision needed:** ML-KEM-768 (current hybrid default) vs ML-KEM-1024.

---

## 6. ML-KEM based `scka.Provider` (Chosen Design – Option 1)

**Decision locked:** The project will implement a **thin, custom ML-KEM SCKA provider** under our direct control. This avoids external license constraints (AGPL) and keeps the post-quantum continuous-key-agreement logic fully auditable and modifiable by the team.

The Go Triple Ratchet library (`go-doubleratchet`) and any faithful SPQR implementation require a real **Sparse Continuous Key Agreement (SCKA) provider**. The mock provider shipped for tests is **not** suitable for production.

### 6.1 Required Interface

The provider must implement the continuous post-quantum key-agreement steps used by SPQR:

```text
scka.Provider
├── KeyGen()                  → ML-KEM key pair (public + secret)
├── Encaps(pk)                → (ciphertext, shared_secret)
├── Decaps(sk, ct)            → shared_secret
├── DerivePQContribution(...) → bytes mixed into the hybrid KDF
└── Chunk / epoch helpers     → support sparse transmission of large ML-KEM values
```

### 6.2 Implementation Guidance (Thin Provider)

- **Primitive source (preferred order):**
  1. `libcrux-ml-kem` (Rust) – same library Signal uses in production SPQR.
  2. RustCrypto `ml-kem` crate – pure Rust, widely used, FIPS 203.
  3. `liboqs` / official bindings – acceptable for early prototyping; prefer pure-Rust for final build.

- The provider should follow the SPQR “braid” / epoch model:
  - Full ML-KEM public keys or ciphertexts are **not** sent in every message.
  - Material is split into chunks and protected with erasure coding so that any sufficient subset of chunks reconstructs the value.
  - This keeps per-message overhead practical inside the TCP payload budget (~176 bytes reserved).

- The provider is responsible only for the post-quantum continuous key-agreement contribution. The classical Double Ratchet and the final hybrid KDF remain outside it.

### 6.3 Security Requirements (Mandatory)

The `scka.Provider` is part of the Trusted Computing Base. A weak or incorrect provider destroys the post-quantum half of the hybrid guarantee. It **must**:

- Use a NIST-standardized ML-KEM parameter set (ML-KEM-768 recommended as default; ML-KEM-1024 optional for higher margin).
- Zeroize all secret material on drop / error paths.
- Reject invalid ciphertexts and public keys.
- Be constant-time for secret-dependent operations where feasible.
- Never log or persist raw shared secrets or secret keys longer than necessary.

### 6.4 Why Option 1 Was Chosen

- Full control over the post-quantum continuous ratchet logic.
- No AGPL dependency from Signal’s official SPQR crate.
- Easier to adapt the chunking / epoch behaviour to our transport framing and size budgets.
- Clear ownership for security review and future algorithm updates.

---

## 7. Self-Healing Properties

- **Forward Secrecy:** Compromise of a message key does not expose previous messages.
- **Post-Compromise Security (PCS):** After an attacker loses access, subsequent public-ratchet advances restore security for future messages.
- Hybrid security: an attacker must break **both** the classical (X25519) and post-quantum (ML-KEM) assumptions to recover any final message key.
- SPQR chunking + erasure coding limits the impact of packet loss on the post-quantum ratchet.

---

## 8. Library API Requirements (C ABI)

The library remains transport-agnostic. Suggested surface (updated for online handshake):

```c
typedef struct tr_session tr_session_t;

tr_session_t *tr_session_new(void);
void          tr_session_free(tr_session_t *s);

/* Online PQXDH-style handshake */
int tr_session_handshake_init(tr_session_t *s, uint8_t *out_msg, size_t *out_len);
int tr_session_handshake_respond(tr_session_t *s,
                                 const uint8_t *in_msg, size_t in_len,
                                 uint8_t *out_msg, size_t *out_len);
int tr_session_handshake_finish(tr_session_t *s,
                                const uint8_t *in_msg, size_t in_len);

/* Messaging */
int tr_session_encrypt(tr_session_t *s,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len,
                       uint8_t *header, size_t *hdr_len);

int tr_session_decrypt(tr_session_t *s,
                       const uint8_t *header, size_t hdr_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len);

/* Optional persistence */
int tr_session_export_state(tr_session_t *s, uint8_t *buf, size_t *len);
int tr_session_import_state(tr_session_t *s, const uint8_t *buf, size_t len);
```

All sensitive material must be zeroized on free / error paths.  
No network I/O inside the library.

---

## 9. Framing & Size Budgets (Unchanged)

- Fixed framing overhead: ~16 bytes  
- Typical ratchet + AEAD overhead: 128–176 bytes reserved  
- Recommended `TR_MAX_PLAINTEXT`: 1024–1100 bytes (fits comfortably under common MSS values)

---

## 10. Reuse Guidance (Go Triple Ratchet)

**Primary candidate:** `github.com/KushnerykPavel/go-doubleratchet` (MIT)

**Reuse:**
- `TripleRatchetSession` logic
- Hybrid KDF approach
- Header composition ideas
- X25519 and KDF helpers

**Must still be supplied / replaced:**
- Real ML-KEM `scka.Provider` (see Section 6)
- Modern AEAD instead of CBC+HMAC where present
- Online PQXDH-style handshake wrapper
- Transport framing and session lifecycle

**Security posture of the Go library:** useful design reference, but pre-1.0, unofficial, unaudited. Do not treat it as a finished high-assurance component.

---

## 11. Implementation Phases (Updated)

### Phase 0 – Foundations
- [ ] Online PQXDH-style handshake (X25519 + ML-KEM)
- [ ] Shared-secret → Triple Ratchet initialization
- [ ] Basic unit tests for handshake + first message

### Phase 1 – Core Ratchet + SCKA Provider
- [ ] Integrate or re-implement Triple Ratchet
- [ ] Production ML-KEM `scka.Provider`
- [ ] Hybrid KDF and AEAD path
- [ ] Round-trip encrypt/decrypt test vectors

### Phase 2 – Session + Framing
- [ ] TCP/UDP payload framing
- [ ] State export/import
- [ ] Out-of-order / skipped-key bounds

### Phase 3 – Packaging & Hardening
- [ ] C ABI + headers
- [ ] `.deb` / `.rpm` / Homebrew
- [ ] CI matrix and basic side-channel hygiene

---

## 12. Open Decisions for Build Session

1. ML-KEM parameter set: **768** (recommended default) or **1024**?
2. Concrete library for the thin ML-KEM provider: `libcrux-ml-kem` vs RustCrypto `ml-kem` (Go bindings if staying in Go).
3. AEAD choice: XChaCha20-Poly1305 vs AES-256-GCM?
4. Whether the core Triple Ratchet engine stays in Go or moves to Rust (the SCKA provider can be Rust even if the engine is Go via FFI).
5. Identity binding: pure ephemeral, or add long-term identity keys later?

---

## 13. Security Notes

- Recipient **must** be online; there is no offline pre-key mode.
- The security of the post-quantum half rests entirely on the quality of the `scka.Provider`.
- Hybrid KDF must be implemented so that breaking only one of X25519 or ML-KEM is insufficient.
- Associated data must bind host identities / session identifiers.
- Skipped-message-key caches must be strictly bounded (DoS resistance).
- This remains a **custom protocol**; interoperability with TLS or Signal is not a goal.

---

## 14. References

- Signal Blog – “Signal Protocol and Post-Quantum Ratchets” (2025-10-02)
- Signal Double Ratchet Specification (Triple Ratchet section)
- Signal SparsePostQuantumRatchet repository
- PQXDH / hybrid key-exchange designs (Signal, IETF drafts)
- NIST FIPS 203 – ML-KEM
- `github.com/KushnerykPavel/go-doubleratchet` (MIT, unofficial Triple Ratchet)

---

**End of Target Spec v0.3**  
Primary change from v0.2: locked in Option 1 – a thin, custom ML-KEM `scka.Provider` under project control. Removed alternative provider strategies as primary paths.
