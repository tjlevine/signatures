const schnorr = require('./schnorr');
const { PrivateKey } = require('./keys');

console.log(`=== SCHNORR SIGNATURE ===`);
const message = 'schnorr is awesome';
console.log(`Signing message:\n${message}`);
const messageBuf = Buffer.from(message);
console.log(`message buffer:\n${messageBuf.toString('hex')}`);
const prv = new PrivateKey();
console.log(`private key:\n${prv.toBigInteger().toString(16)}`);
const signer = new schnorr.Signer(prv, messageBuf);
const sig = signer.sign();
console.log(`signature:\nR: ${sig.R.toString('hex')}\ns: ${sig.s.toString('hex')}`);
const verifier = new schnorr.Verifier(sig, prv.toPublicKey(), messageBuf);
console.log(`Verified? ${verifier.verify()}`);