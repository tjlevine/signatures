import winston from 'winston';

import { PrivateKey } from './keys';
import * as schnorr from './schnorr';

const { format, transports } = winston;

const log: winston.Logger = winston.createLogger({
    format: format.combine(
        format.colorize(),
        format.splat(),
        format.simple(),
    ),
    transports: [new transports.Console()],
});

log.info('=== SCHNORR SIGNATURE ===');
const message: string = 'schnorr is awesome';
log.info(`Signing message:\n${message}`);
const messageBuf: Buffer = Buffer.from(message);
log.info('message buffer: %s', messageBuf.toString('hex'));
const prv: PrivateKey = new PrivateKey();
log.info('private key: %s', prv.toBigInteger().toString(16));
const signer: schnorr.Signer = new schnorr.Signer(prv, messageBuf);
const sig: schnorr.Signature = signer.sign();
log.info('signature:\nR: %s\ns: %s', sig.R.toString('hex'), sig.s.toString('hex'));
const verifier: schnorr.Verifier = new schnorr.Verifier(sig, prv.toPublicKey(), messageBuf);
log.info('Verified? %s', verifier.verify());
