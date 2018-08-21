import BigInteger from 'bigi';
import crypto from 'crypto';
import ecurve from 'ecurve';

import PublicKey from './PublicKey';

const curve: ecurve.Curve = ecurve.getCurveByName('secp256k1');

export default class PrivateKey {
    private buf: Buffer;

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
