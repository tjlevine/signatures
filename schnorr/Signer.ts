import BigInteger from 'bigi';
import crypto from 'crypto';
import ecurve from 'ecurve';
import hash from '../hash';
import { PrivateKey } from '../keys/secp';
import Signature from './Signature';

const curve: ecurve.Curve = ecurve.getCurveByName('secp256k1');

export default class Signer {
  public prv: PrivateKey;
  public message: Buffer;

  constructor(privateKey: PrivateKey, message: Buffer) {
    this.prv = privateKey;
    this.message = message;
  }

  public sign(): Signature {
    // generate random integer r between 0 and curve.n (probably)
    const r: BigInteger = BigInteger.fromBuffer(crypto.randomBytes(curve.n.byteLength()));

    // multiply by generator to get preimage point
    const bigR: ecurve.Point = curve.G.multiply(r);

    // concat encoded preimage point and message to create full preimage
    const preimage: Buffer = Buffer.concat([bigR.getEncoded(true), this.message]);

    // c is the integer image
    const c: BigInteger = BigInteger.fromBuffer(hash(preimage));

    // x is the integer prv
    const x: BigInteger = this.prv.toBigInteger();

    // s = r + cx
    const s: BigInteger = r.add(c.multiply(x)).mod(curve.n);

    // signature is (R, s)
    return new Signature(bigR, s);
  }
}
