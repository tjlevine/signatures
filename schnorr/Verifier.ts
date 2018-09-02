import BigInteger from 'bigi';
import ecurve from 'ecurve';

import hash from '../hash';
import { PublicKey } from '../keys/secp';
import Signature from './Signature';

const curve = ecurve.getCurveByName('secp256k1');

export default class Verifier {
  public sig: Signature;
  public pub: PublicKey;
  public message: Buffer;
  private isValid?: boolean = undefined;

  constructor(sig: Signature, pub: PublicKey, message: Buffer) {
    this.sig = sig;
    this.pub = pub;
    this.message = message;
  }

  // verification equation:
  // Given pubkey Q = xG, message m, and signature (R, s)
  // sG =? R + H(R, m)Q
  // sG =? rG + H(R, m)xG
  // sG =? (r + cx)G
  // sG =? sG
  // if this equation holds, then the signature is valid
  public verify() {
    if (this.isValid !== undefined) {
      return this.isValid;
    }

    // decode the preimage point from the signature
    const bigR: ecurve.Point = ecurve.Point.decodeFrom(curve, this.sig.R);

    // create the preimage
    const preimage: Buffer = Buffer.concat([bigR.getEncoded(true), this.message]);

    // c is the integer image
    const c: BigInteger = BigInteger.fromBuffer(hash(preimage));

    // right side of verification equation is R + cQ
    const right: ecurve.Point = bigR.add(this.pub.point.multiply(c));

    // left side is sG
    const left: ecurve.Point = curve.G.multiply(BigInteger.fromBuffer(this.sig.s));

    // signature is valid if sG == R + cQ
    this.isValid = left.equals(right);
    return this.isValid;
  }
}
