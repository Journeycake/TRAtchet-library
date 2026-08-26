import type { ReactNode } from "react";
import { LabNav } from "@/components/lab/lab-nav";
import {
  AEAD_NAME,
  CLASSICAL_DH,
  HEADER_LEN,
  MAX_PLAINTEXT,
  MAX_SKIP,
  MLKEM_CT_LEN,
  MLKEM_PARAM,
  MLKEM_PK_LEN,
  PROTOCOL_VERSION,
  RECORD_LEN_SIZE,
  SPQR_CHUNK,
  SPQR_CHUNKS_PER_MSG,
} from "@/lib/tratchet";

export function ProtocolPage() {
  return (
    <div className="min-h-dvh bg-bg text-fg">
      <LabNav current="protocol" />

      <article className="mx-auto max-w-3xl px-4 py-10 lg:py-14">
        <p className="font-mono text-xs tracking-wide text-accent">v0.3 · session layer</p>
        <h1 className="mt-2 text-3xl font-medium tracking-tight text-fg lg:text-4xl">
          Online PQXDH handshake plus Triple Ratchet
        </h1>
        <p className="mt-4 text-base leading-relaxed text-muted">
          TRatchet is a transport-agnostic cryptographic session. Callers supply
          UDP, TCP, or any byte pipe. The library never performs network I/O.
          Linux hosts in this lab wrap records in a {RECORD_LEN_SIZE}-byte
          length prefix so a TCP or Unix stream can delimit messages. This page
          is the locked build plan; the lab and the host pair run the same
          TypeScript engine.
        </p>

        <Section title="Locked decisions">
          <Table
            rows={[
              ["ML-KEM set", `${MLKEM_PARAM} (NIST level 3)`],
              ["Classical DH", CLASSICAL_DH],
              ["AEAD", AEAD_NAME],
              ["KDF", "HKDF-SHA256 + HMAC-SHA256 chain"],
              ["Engine", "TypeScript (portable; C ABI later via WASM)"],
              ["SCKA provider", "Thin custom ML-KEM-768 under project control"],
              ["Identity", "Pure ephemeral; session id bound as AAD"],
              ["Primitive source", "@noble/post-quantum (FIPS 203) + @noble/curves"],
            ]}
          />
        </Section>

        <Section title="Phase 1 — online handshake">
          <p>
            Both hosts must be reachable. There is no offline pre-key bundle.
            Initiator sends ephemeral X25519 public key, ML-KEM-768 encapsulation
            key ({MLKEM_PK_LEN} B), and a nonce. Responder replies with its
            X25519 public key, ML-KEM ciphertext ({MLKEM_CT_LEN} B), and nonce.
            Shared secret is HKDF of the DH output concatenated with the KEM
            shared secret — breaking only one primitive is not enough.
          </p>
          <ol className="mt-4 space-y-2 font-mono text-sm text-muted">
            <li>1. Alpha → INIT (TR1I) · sid · nonce · X25519 pk · ML-KEM pk</li>
            <li>2. Bravo → RESP (TR1R) · sid · nonce · X25519 pk · ML-KEM ct</li>
            <li>3. Both derive RK, sending/receiving chains, and PQ chains</li>
          </ol>
        </Section>

        <Section title="Phase 2 — Triple Ratchet">
          <p>
            Every application message advances the classical Double Ratchet
            (X25519 + symmetric chain) and the sparse post-quantum ratchet in
            lockstep. The final message key is
          </p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-bg-elevated p-4 font-mono text-xs text-accent shadow-[var(--shadow-border)]">
            {`final_mk = HKDF(ec_mk || pq_mk, info="TRATCHET-HYBRID-MK-v1")
nonce    = 24 bytes from the same HKDF
AEAD     = XChaCha20-Poly1305(final_mk, nonce, aad=sid||header)`}
          </pre>
          <p className="mt-4">
            Direction change triggers a sending DH ratchet on the next encrypt
            and a matching receiving ratchet on decrypt — post-compromise
            security for the classical half. SPQR epochs mix a fresh ML-KEM
            shared secret into both PQ chains once the offeror installs it.
          </p>
        </Section>

        <Section title="Sparse PQ ratchet (SCKA)">
          <p>
            Full ML-KEM public keys and ciphertexts are not sent on every
            message. Material is split into {SPQR_CHUNK}-byte chunks with a
            single XOR parity so any one lost frame can be recovered. Each data
            header carries {SPQR_CHUNKS_PER_MSG} chunks ({SPQR_CHUNK * SPQR_CHUNKS_PER_MSG} B). Odd epochs: initiator
            offers a PK; responder encapsulates. Even epochs reverse the roles.
          </p>
          <p>
            That budget is why a new epoch looks chatty if the session is quiet.
            An ML-KEM-768 public key is {MLKEM_PK_LEN.toLocaleString()} bytes;
            ciphertext is {MLKEM_CT_LEN.toLocaleString()} bytes. At 128 bytes of
            chunks per header you need about 10 frames to offer a PK and 10 more
            to return the CT, plus one install. Those frames are supposed to be
            real application messages with chunks in the header. The lab's
            Complete epoch button only emits empty in-band frames so you can
            finish the epoch without typing 20 payloads.
          </p>
          <Table
            rows={[
              ["Header size", `${HEADER_LEN} B (fixed)`],
              ["Stream prefix", `${RECORD_LEN_SIZE} B length (TCP / Unix)`],
              ["Chunk size", `${SPQR_CHUNK} B`],
              ["Chunks / message", `${SPQR_CHUNKS_PER_MSG} (${SPQR_CHUNK * SPQR_CHUNKS_PER_MSG} B)`],
              ["PK / CT", `${MLKEM_PK_LEN} B / ${MLKEM_CT_LEN} B`],
              ["Quiet-session frames", "~10 PK + ~10 CT + 1 install"],
              ["Max plaintext", `${MAX_PLAINTEXT} B`],
              ["Skipped-key bound", String(MAX_SKIP)],
              ["Protocol version", String(PROTOCOL_VERSION)],
            ]}
          />
        </Section>

        <Section title="Self-healing">
          <ul className="space-y-2 text-muted">
            <li>
              <span className="text-fg">Forward secrecy.</span> Each message
              key is one-way derived; leaking MK_n does not expose MK_n-1.
            </li>
            <li>
              <span className="text-fg">Post-compromise security.</span> After
              the attacker loses access, a DH ratchet plus a completed PQ epoch
              restore both halves of the hybrid guarantee.
            </li>
            <li>
              <span className="text-fg">Hybrid binding.</span> An attacker must
              break X25519 and ML-KEM-768 to recover any final message key.
            </li>
          </ul>
        </Section>

        <Section title="C ABI surface (later packaging)">
          <pre className="overflow-x-auto rounded-lg bg-bg-elevated p-4 font-mono text-xs leading-relaxed text-muted shadow-[var(--shadow-border)]">{`tr_session_t *tr_session_new(void);
void          tr_session_free(tr_session_t *s);
int tr_session_handshake_init(tr_session_t *s, uint8_t *out, size_t *len);
int tr_session_handshake_respond(tr_session_t *s, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len);
int tr_session_handshake_finish(tr_session_t *s, const uint8_t *in, size_t in_len);
int tr_session_encrypt(tr_session_t *s, const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len, uint8_t *hdr, size_t *hdr_len);
int tr_session_decrypt(tr_session_t *s, const uint8_t *hdr, size_t hdr_len,
                       const uint8_t *ct, size_t ct_len, uint8_t *pt, size_t *pt_len);
int tr_session_export_state(tr_session_t *s, uint8_t *buf, size_t *len);
int tr_session_import_state(tr_session_t *s, const uint8_t *buf, size_t len);`}</pre>
          <p className="mt-3 text-sm text-muted">
            The TypeScript <code className="font-mono text-fg">Session</code> class
            matches this surface today. Packaging (.deb, .rpm, Homebrew) is Phase 3.
          </p>
        </Section>

        <Section title="Implementation phases">
          <ol className="space-y-3">
            <Phase n="0" title="Foundations" done>
              Online PQXDH, shared-secret → ratchet init, handshake unit tests.
            </Phase>
            <Phase n="1" title="Core ratchet + SCKA" done>
              Double Ratchet, ML-KEM provider, hybrid KDF, XChaCha20-Poly1305,
              SPQR chunking with parity, round-trip vectors.
            </Phase>
            <Phase n="2" title="Session + framing" done>
              Fixed 176-byte headers, skipped-key bounds, export/import, lab
              wire with drop/deliver.
            </Phase>
            <Phase n="3" title="Packaging">
              C ABI via WASM, .deb / .rpm / Homebrew, CI matrix, identity
              binding with long-term keys.
            </Phase>
          </ol>
        </Section>

        <p className="mt-12 font-mono text-xs text-subtle">
          Custom protocol. Not interoperable with TLS, WireGuard, or Signal.
          Recipient must be online. No formal verification in this phase.
        </p>
      </article>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="mt-12">
      <h2 className="text-lg font-medium tracking-tight text-fg">{title}</h2>
      <div className="mt-3 space-y-3 text-base leading-relaxed text-muted">{children}</div>
    </section>
  );
}

function Table({ rows }: { rows: [string, string][] }) {
  return (
    <div className="mt-4 overflow-hidden rounded-lg shadow-[var(--shadow-border)]">
      <table className="w-full text-left text-sm">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k} className="border-b border-border last:border-0">
              <th className="w-40 bg-bg-elevated px-3 py-2.5 font-mono text-xs font-medium text-muted">
                {k}
              </th>
              <td className="px-3 py-2.5 font-mono text-xs text-fg">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Phase({
  n,
  title,
  done,
  children,
}: {
  n: string;
  title: string;
  done?: boolean;
  children: ReactNode;
}) {
  return (
    <li className="flex gap-3">
      <span
        className={
          done
            ? "mt-0.5 size-2 shrink-0 rounded-full bg-accent"
            : "mt-0.5 size-2 shrink-0 rounded-full bg-subtle"
        }
      />
      <div>
        <p className="font-medium text-fg">
          Phase {n} — {title}
        </p>
        <p className="text-sm text-muted">{children}</p>
      </div>
    </li>
  );
}
