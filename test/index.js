'use strict';
// Load modules

const Code = require('code');
const Crypto = require('crypto');
const Lab = require('lab');

const auth = require('../lib/auth');
const userAuth = require('../lib/userAuth');

// Declare internals

const internals = {};

// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;

describe('auth.verify', () => {

  lab.before((done) => {

    internals.testPassword = 'Pass!23';

    internals.testSalt = Crypto.randomBytes(128).toString('base64');

    Crypto.pbkdf2(internals.testPassword, internals.testSalt, 10000, 512, 'sha1', (err, dk) => {
      internals.testHash = new Buffer(dk, 'binary').toString('hex');
      done();
    });
  });

  it('verifies password with hash and salt', async () => {

    let isVerified;
    try {
      isVerified = await auth.verify(internals.testPassword, internals.testHash, internals.testSalt);
    } catch (err) {
      expect(err).to.not.exist();
    }
    expect(isVerified).to.equal(true);
  });

  it('fails to verify non-matching password with hash and salt', async () => {

    let isVerified;
    try {
      isVerified = await auth.verify('someotherpassword', internals.testHash, internals.testSalt);
    } catch (err) {
      expect(err).to.not.exist();
    }
    expect(isVerified).to.equal(false);
  });

  it('throws error when password is missing', async () => {

    let callErr;
    try {
      await auth.verify(null, internals.testHash, internals.testSalt);
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();
  });

  it('throws error when salt is missing', async () => {

    let callErr;
    try {
      await auth.verify(internals.testPassword, internals.testHash, null);
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();
  });

});

describe('auth.hash', () => {

  lab.before(async () => {

    internals.testPassword = 'Pass!23';

  });

  it('hashes a password and returns hash and salt', async () => {

    const {hash, salt} = await auth.hash(internals.testPassword);
    expect(hash).to.exist();
    expect(salt).to.exist();

  });

  it('hashes a password and returns hash and salt which can then be verified', async () => {

    try {

      const {hash, salt} = await auth.hash(internals.testPassword);
      const isVerified = await auth.verify(internals.testPassword, hash, salt);

      expect(isVerified).to.equal(true);

    } catch (err) {
      expect(err).to.not.exist();
    }
  });

  it('throws error when password is missing', async () => {

    let callErr;

    try {
      await auth.hash();
    } catch (err) {
      callErr = err;
    }

    expect(callErr).to.exist();
  });

  it('throws error when password is less than 6 characters', async () => {

    let callErr;

    try {
      await auth.hash('Pas!2');
    } catch (err) {
      callErr = err;
    }

    expect(callErr).to.exist();
  });

  it('throws error when password has only 1 valid characteristic', async () => {

    let callErr;

    try {
      await auth.hash('password');
    } catch (err) {
      callErr = err;
    }

    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('123456');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('PASSWORD');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('!@#$%^');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

  });

  it('throws error when password has only 2 valid characteristics', async () => {

    let callErr;

    try {
      await auth.hash('Password');
    } catch (err) {
      callErr = err;
    }

    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('p23456');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('PASSW1RD');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

    callErr = null;

    try {
      await auth.hash('p@#$%^');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

  });

  it('hashes a password when it has 3 valid characteristics', async () => {

    try {
      const {hash, salt} = await auth.hash('Passw1rd');
      expect(hash).to.exist();
      expect(salt).to.exist();
    } catch (err) {
      expect(err).to.not.exist();
    }

    try {
      const {hash, salt} = await auth.hash('Pass!23');
      expect(hash).to.exist();
      expect(salt).to.exist();
    } catch (err) {
      expect(err).to.not.exist();
    }

    try {
      const {hash, salt} = await auth.hash('a#Fasdf');
      expect(hash).to.exist();
      expect(salt).to.exist();
    } catch (err) {
      expect(err).to.not.exist();
    }

    try {
      const {hash, salt} = await auth.hash('HELP@2');
      expect(hash).to.exist();
      expect(salt).to.exist();
    } catch (err) {
      expect(err).to.not.exist();
    }
  });

});

describe('userAuth.generate', () => {

  it('returns user object with hash and salt fields', async () => {

    try {
      const {hash, salt} = await userAuth.generate('hapPy3');
      expect(hash).to.exist();
      expect(salt).to.exist();
    } catch (err) {
      expect(err).to.not.exist();
    }

  });

  it('throws error when password is missing', async () => {

    let callErr;

    try {
      await userAuth.generate(null);
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

  });

});

describe('userAuth.authenticate', () => {

  lab.before((done) => {

    internals.testPassword = 'Pass!23';

    internals.testSalt = Crypto.randomBytes(128).toString('base64');

    Crypto.pbkdf2(internals.testPassword, internals.testSalt, 10000, 512, 'sha1', (err, dk) => {
      internals.testHash = new Buffer(dk, 'binary').toString('hex');
      internals.testUser = {
        hash: internals.testHash,
        salt: internals.testSalt
      };
      done();
    });
  });

  it('verifies password matches users hash and salt', async () => {

    try {
      const isAuthenticated = await userAuth.authenticate(internals.testPassword, internals.testUser);
      expect(isAuthenticated).to.equal(true);
    } catch (err) {
      expect(err).to.not.exist();
    }

  });

  it('fails to verify when password does not match users hash and salt', async () => {

    try {
      const isAuthenticated = await userAuth.authenticate('No7UrP@ss0rd', internals.testUser);
      expect(isAuthenticated).to.equal(false);
    } catch (err) {
      expect(err).to.not.exist();
    }

  });

  it('throws error when password is missing', async () => {

    let callErr;

    try {
      await userAuth.authenticate(null, {});
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

  });

  it('throws error when user object is missing', async () => {

    let callErr;

    try {
      await userAuth.authenticate('hapPy3');
    } catch (err) {
      callErr = err;
    }
    expect(callErr).to.exist();

  });

});