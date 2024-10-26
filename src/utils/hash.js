const crypto = require('crypto');

exports.calculateHash = (content) => {
  return crypto.createHash('sha256').update(content).digest('hex');
};
