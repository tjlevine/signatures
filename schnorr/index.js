const ecurve = require('ecurve');
const crypto = require('crypto');
const BigInteger = require('bigi');
const { hash } = require('../util');

const curve = ecurve.getCurveByName('secp256k1');

module.exports.Signature = class Signature {
  constructor(R, s) {
    this.R = R.getEncoded(true);
    this.s = s.toBuffer(32);
  }
}

module.exports.Signer = class Signer {
  constructor(privateKey, message) {
    this.prv = privateKey;
    this.message = message;
  }

  sign() {
    // generate random integer r between 0 and curve.n (probably)
    const r = BigInteger.fromBuffer(crypto.randomBytes(curve.n.byteLength()));

    // multiply by generator to get preimage point
    const bigR = curve.G.multiply(r);

    // concat encoded preimage point and message to create full preimage
    const preimage = Buffer.concat([bigR.getEncoded(true), this.message]);

    // c is the integer image
    const c = BigInteger.fromBuffer(hash(preimage));

    // x is the integer prv
    const x = this.prv.toBigInteger();

    // s = r + cx
    const s = r.add(c.multiply(x)).mod(curve.n);

    // signature is (R, s)
    return new module.exports.Signature(bigR, s);
  }
}

// verification equation:
// Given pubkey Q = xG, message m, and signature (R, s)
// sG =? R + H(R, m)Q
// sG =? rG + H(R, m)xG
// sG =? (r + cx)G
// sG =? sG
// if this equation holds, then the signature is valid
module.exports.Verifier = class Verifier {
  constructor(sig, pub, message) {
    this.sig = sig;
    this.pub = pub;
    this.message = message;
  }

  verify() {
    if (this.isValid !== undefined) {
      return this.isValid;
    }

    // decode the preimage point from the signature
    const bigR = ecurve.Point.decodeFrom(curve, this.sig.R);

    // create the preimage
    const preimage = Buffer.concat([bigR.getEncoded(true), this.message]);

    // c is the integer image
    const c = BigInteger.fromBuffer(hash(preimage));

    // right side of verification equation is R + cQ
    const right = bigR.add(this.pub.Q.multiply(c));

    // left side is sG
    const left = curve.G.multiply(BigInteger.fromBuffer(this.sig.s));

    // signature is valid if sG == R + cQ
    this.isValid = left.equals(right);
    return this.isValid;
  }
}
