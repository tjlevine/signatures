const crypto = require('crypto');

module.exports.hash = (preimage) => crypto.createHash('sha256').update(preimage).digest();