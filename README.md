# TRatchet

Session-layer hybrid ratchet for host-to-host communication. v0.4 **reference** — not a production cryptographic suite.

Repo: [Journeycake/TRAtchet-library](https://github.com/Journeycake/TRAtchet-library) (GPL-3.0).

The library performs **no network I/O**. Callers supply TCP, a Unix socket, or any byte pipe. This repo also includes an interactive lab (handshake, wire inspector, Node host pair).

## Status

| | |
|---|---|
| Spec | v0.4 online PQXDH + Triple Ratchet (SPQR) + Ed25519 identities |
| Handshake | X25519 + ML-KEM-768, two flights, Ed25519 signatures |
| Data | Double Ratchet (X25519) + sparse PQ epoch, hybrid HKDF, XChaCha20-Poly1305 |
| Header | 176 B fixed; 2×64 B SPQR chunks |
| Stream framing | 4 B big-endian length prefix |
| License | GPL-3.0-or-later |

**Do not ship this as a TLS replacement yet.** See [SECURITY.md](SECURITY.md). Without a peer pin, first-contact TOFU is still MITM-able.

## Layout

```
src/lib/tratchet/               protocol library (no I/O except node-host.ts)
src/lib/tratchet/node-host.ts   length-prefixed TCP / Unix pair
src/components/lab/             interactive lab
docs/spec.md                    build target spec
```

## Library API

```ts
import { Session, identityKeygen } from "./src/lib/tratchet/index.ts";

const idA = identityKeygen();
const idB = identityKeygen();

const a = new Session({ identity: idA, peerIdentity: idB.publicKey });
const b = new Session({ identity: idB, peerIdentity: idA.publicKey });

const offer = a.handshakeInit();
const reply = b.ingestHandshake(offer);
a.ingestHandshake(reply!);

const { header, ciphertext } = a.encrypt(payload);
const plain = b.decrypt(header, ciphertext);
```

Omit `peerIdentity` for TOFU (accept whatever identity signed the handshake). On a stream, wrap each handshake blob or `header ‖ ciphertext` with `encodeRecord` from `framing.ts`.

## Tests

```sh
npm install
npm run test:protocol
```

Requires Node 22. Primitives: `@noble/curves`, `@noble/ciphers`, `@noble/hashes`, `@noble/post-quantum`.

## Linux hosts

Two processes, same library:

1. Responder binds TCP or a Unix socket (prefer a `0700` directory + `chmod 0600` + `SO_PEERCRED` — not yet in this tree).
2. Initiator connects.
3. Exchange two handshake records, then data records.

The Hosts lab runs that path on a kernel socket and prints bind, record sizes, and session id.
