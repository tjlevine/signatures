import crypto from 'crypto';

export default (preimage: Buffer): Buffer => crypto.createHash('sha256').update(preimage).digest();
