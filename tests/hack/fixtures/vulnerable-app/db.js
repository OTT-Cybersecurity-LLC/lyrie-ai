// Stub DB for the vulnerable-app fixture. Not exercised at runtime by tests.
module.exports = {
  query(_sql, cb) {
    cb(null, []);
  },
};
