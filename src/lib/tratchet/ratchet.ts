import { fingerprint, zeroize } from "./bytes.ts";
import { kdfCk, kdfRk } from "./kdf.ts";
import type { HandshakeSecrets } from "./handshake.ts";
import { dhKeygen, dhShared, type DhKeyPair } from "./x25519.ts";
import { equalBytes } from "./bytes.ts";

export class DoubleRatchet {
  rk: Uint8Array;
  cks: Uint8Array;
  ckr: Uint8Array;
  dhs: DhKeyPair;
  dhr: Uint8Array;
  ns = 0;
  nr = 0;
  pn = 0;
  lastEcMkFp = "";

  constructor(secrets: HandshakeSecrets) {
    this.rk = secrets.root;
    this.dhs = secrets.dh;
    this.dhr = secrets.dhRemote;
    if (secrets.role === "initiator") {
      this.cks = secrets.ckInit;
      this.ckr = secrets.ckResp;
    } else {
      this.cks = secrets.ckResp;
      this.ckr = secrets.ckInit;
    }
  }

  sendStep(): { mk: Uint8Array; n: number; pn: number; dhPub: Uint8Array } {
    const { ck, mk } = kdfCk(this.cks);
    this.cks = ck;
    const n = this.ns;
    this.ns += 1;
    this.lastEcMkFp = fingerprint(mk);
    return { mk, n, pn: this.pn, dhPub: this.dhs.publicKey };
  }

  recvStep(): Uint8Array {
    const { ck, mk } = kdfCk(this.ckr);
    this.ckr = ck;
    this.nr += 1;
    this.lastEcMkFp = fingerprint(mk);
    return mk;
  }

  receivingRatchet(theirPub: Uint8Array): void {
    this.nr = 0;
    this.dhr = theirPub.slice();
    const dhOut = dhShared(this.dhs.secretKey, this.dhr);
    const r = kdfRk(this.rk, dhOut);
    zeroize(this.rk, dhOut);
    this.rk = r.rk;
    this.ckr = r.ck;
  }

  sendingRatchet(): void {
    this.pn = this.ns;
    this.ns = 0;
    zeroize(this.dhs.secretKey);
    this.dhs = dhKeygen();
    const dhOut = dhShared(this.dhs.secretKey, this.dhr);
    const r = kdfRk(this.rk, dhOut);
    zeroize(this.rk, dhOut);
    this.rk = r.rk;
    this.cks = r.ck;
  }

  sameRemote(pub: Uint8Array): boolean {
    return equalBytes(this.dhr, pub);
  }
}
