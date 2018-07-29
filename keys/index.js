const crypto = require('crypto');
const BigInteger = require('bigi');
const curve = require('ecurve').getCurveByName('secp256k1');

module.exports.PublicKey = class PublicKey {
    constructor(pubPoint) {
        this.Q = pubPoint;
    }

    toBuffer() {
        return this.Q.getEncoded(true);
    }
}

module.exports.PrivateKey = class PrivateKey {
    constructor(seed) {
        if (seed) {
            this.buf = Buffer.from(seed, 'hex');
        } else {
            this.buf = crypto.randomBytes(curve.n.byteLength());
        }
    }

    toBigInteger() {
        return BigInteger.fromBuffer(this.buf);
    }

    toPublicKey() {
        return new module.exports.PublicKey(curve.G.multiply(this.toBigInteger()));
    }
}