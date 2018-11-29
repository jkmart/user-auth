'use strict';

// Load modules
const Code = require('code');
const Crypto = require('crypto');
const Lab = require('lab');

const { before, describe, it } = exports.lab = Lab.script();

const Hash = require('../lib/hash');
const Auth = require('../lib/auth');

// Set crypto encoding
Crypto.DEFAULT_ENCODING = 'hex';

// Declare internals
const internals = {};

const { expect } = Code;

describe('Hash.verify', () => {

    before(async () => {

        internals.testPassword = 'Pass!23';

        internals.testSalt = Crypto.randomBytes(128).toString('base64');

        return await new Promise((resolve, reject) => {

            Crypto.pbkdf2(internals.testPassword, internals.testSalt, 10000,
                512,
                'sha1', (err, dk) => {

                    if (err) {
                        reject(err);
                    }

                    internals.testHash = dk;
                    resolve();
                });
        });
    });

    it('verifies password with hash and salt', async () => {

        let isVerified;
        try {
            isVerified = await Hash.verify(internals.testPassword,
                internals.testHash, internals.testSalt);
        }
        catch (err) {
            expect(err).to.not.exist();
        }

        expect(isVerified).to.equal(true);
    });

    it('fails to verify non-matching password with hash and salt', async () => {

        let isVerified;
        try {
            isVerified = await Hash.verify('someotherpassword',
                internals.testHash, internals.testSalt);
        }
        catch (err) {
            expect(err).to.not.exist();
        }

        expect(isVerified).to.equal(false);
    });

    it('throws error when password is missing', async () => {

        let callErr;
        try {
            await Hash.verify(null, internals.testHash, internals.testSalt);
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();
    });

    it('throws error when salt is missing', async () => {

        let callErr;
        try {
            await Hash.verify(internals.testPassword, internals.testHash, null);
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();
    });

});

describe('Hash.create', () => {

    before(() => {

        internals.testPassword = 'Pass!23';

    });

    it('hashes a password and returns hash and salt', async () => {

        const { hash, salt } = await Hash.create(internals.testPassword);
        expect(hash).to.exist();
        expect(salt).to.exist();

    });

    it('hashes a password and returns hash and salt which can then be verified',
        async () => {

            try {

                const { hash, salt } = await Hash.create(
                    internals.testPassword);
                const isVerified = await Hash.verify(internals.testPassword,
                    hash, salt);

                expect(isVerified).to.equal(true);

            }
            catch (err) {
                expect(err).to.not.exist();
            }
        });

    it('throws error when password is missing', async () => {

        let callErr;

        try {
            await Hash.create();
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();
    });

    it('throws error when password is less than 6 characters', async () => {

        let callErr;

        try {
            await Hash.create('Pas!2');
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();
    });

    it('throws error when password has only 1 valid characteristic',
        async () => {

            let callErr;

            try {
                await Hash.create('password');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('123456');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('PASSWORD');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('!@#$%^');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

        });

    it('throws error when password has only 2 valid characteristics',
        async () => {

            let callErr;

            try {
                await Hash.create('Password');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('p23456');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('PASSW1RD');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

            callErr = null;

            try {
                await Hash.create('p@#$%^');
            }
            catch (err) {
                callErr = err;
            }

            expect(callErr).to.exist();

        });

    it('hashes a password when it has 3 valid characteristics', async () => {

        try {
            const { hash, salt } = await Hash.create('Passw1rd');
            expect(hash).to.exist();
            expect(salt).to.exist();
        }
        catch (err) {
            expect(err).to.not.exist();
        }

        try {
            const { hash, salt } = await Hash.create('Pass!23');
            expect(hash).to.exist();
            expect(salt).to.exist();
        }
        catch (err) {
            expect(err).to.not.exist();
        }

        try {
            const { hash, salt } = await Hash.create('a#Fasdf');
            expect(hash).to.exist();
            expect(salt).to.exist();
        }
        catch (err) {
            expect(err).to.not.exist();
        }

        try {
            const { hash, salt } = await Hash.create('HELP@2');
            expect(hash).to.exist();
            expect(salt).to.exist();
        }
        catch (err) {
            expect(err).to.not.exist();
        }
    });

});

describe('Auth.generate', () => {

    it('returns user object with hash and salt fields', async () => {

        try {
            const { hash, salt } = await Auth.generate('hapPy3');
            expect(hash).to.exist();
            expect(salt).to.exist();
        }
        catch (err) {
            expect(err).to.not.exist();
        }

    });

    it('throws error when password is missing', async () => {

        let callErr;

        try {
            await Auth.generate(null);
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();

    });

});

describe('Auth.authenticate', () => {

    before(async () => {

        internals.testPassword = 'Pass!23';

        internals.testSalt = Crypto.randomBytes(128).toString('base64');

        return await new Promise((resolve, reject) => {

            Crypto.pbkdf2(internals.testPassword, internals.testSalt, 10000,
                512,
                'sha1', (err, dk) => {

                    if (err) {
                        reject(err);
                    }

                    internals.testHash = dk;
                    internals.testUser = {
                        hash: internals.testHash,
                        salt: internals.testSalt
                    };
                    resolve();
                });
        });

    });

    it('verifies password matches users hash and salt', async () => {

        try {
            const isAuthenticated = await Auth.authenticate(
                internals.testPassword, internals.testUser);
            expect(isAuthenticated).to.equal(true);
        }
        catch (err) {
            expect(err).to.not.exist();
        }

    });

    it('fails to verify when password does not match users hash and salt',
        async () => {

            try {
                const isAuthenticated = await Auth.authenticate('No7UrP@ss0rd',
                    internals.testUser);
                expect(isAuthenticated).to.equal(false);
            }
            catch (err) {
                expect(err).to.not.exist();
            }

        });

    it('throws error when password is missing', async () => {

        let callErr;

        try {
            await Auth.authenticate(null, {});
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();

    });

    it('throws error when user object is missing', async () => {

        let callErr;

        try {
            await Auth.authenticate('hapPy3');
        }
        catch (err) {
            callErr = err;
        }

        expect(callErr).to.exist();

    });

});
