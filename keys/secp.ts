import BigInteger from 'bigi';
import crypto from 'crypto';
import ecurve from 'ecurve';

const curve = ecurve.getCurveByName('secp256k1');

export class PrivateKey {
  private readonly buf: Buffer;

  constructor(seed?: string) {
    if (seed) {
      this.buf = Buffer.from(seed, 'hex');
    } else {
      this.buf = crypto.randomBytes(curve.n.byteLength());
    }
  }

  public toBigInteger(): BigInteger {
    return BigInteger.fromBuffer(this.buf);
  }

  public toPublicKey(): PublicKey {
    return new PublicKey(curve.G.multiply(this.toBigInteger()));
  }
}

export class PublicKey {
  constructor(public readonly point: ecurve.Point) {}

  public toBuffer(): Buffer {
    return this.point.getEncoded(true);
  }
}
