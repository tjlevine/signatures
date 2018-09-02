/* tslint:disable:no-unused-expression */

import { expect } from 'chai';

import fixtures from '../fixtures';

import { PrivateKey } from '../../keys';
import * as schnorr from '../../schnorr';

describe('Naive Schnorr', () => {

  it('should sign a message with a random prv', () => {
    const { message } = fixtures.schnorr;

    const messageBuf = Buffer.from(message);
    const prv = new PrivateKey();
    const signer = new schnorr.Signer(prv, messageBuf);
    const sig = signer.sign();

    expect(sig.R).to.be.an.instanceof(Buffer).and.have.lengthOf(33);
    expect(sig.s).to.be.an.instanceof(Buffer).and.have.lengthOf(32);
  });

  it('should verify a signature', () => {
    const { message, prv, sig: { R, s } } = fixtures.schnorr;

    const sig = new schnorr.Signature(R, s);
    const pub = new PrivateKey(prv).toPublicKey();
    const messageBuf = Buffer.from(message);

    const verifier = new schnorr.Verifier(sig, pub, messageBuf);
    expect(verifier.verify()).to.be.true;
  });

});
