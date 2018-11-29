'use strict';

const Boom = require('boom');
const Crypto = require('crypto');
const { promisify } = require('util');
const { validate } = require('./requirements');

// Set Crypto encoding
Crypto.DEFAULT_ENCODING = 'hex';

// Declare internals
const internals = {
    encrypt: promisify(Crypto.pbkdf2),
    isPasswordValid: validate
};

/**
 * Create new encrypted hash
 *
 * @param {string} password Plaintext password
 * @param {string} salt Random bytes used for salt
 * @return {Promise<string>} hash Created hash from encrypt function
 */
internals.createHash = async function (password, salt) {

    let hash;
    try {
        hash = await internals.encrypt(password, salt, 10000, 512, 'sha1');
    }
    catch (err) {
        throw Boom.internal('Could not hash password', err);
    }

    return hash;
};

/**
 * Check a password using a salt and hash to verify
 *
 * @param {string} password
 * @param {string} hash
 * @param {string} salt
 * @return {boolean} isVerified
 */
internals.verifyPassword = async (password, hash, salt) => {

    const key = await internals.createHash(password, salt);

    return key === hash;
};

/**
 * Create new valid password hash with salt
 *
 * @param {string} password
 * @return {{hash: String, salt: String}}
 */
internals.hashPassword = async (password) => {

    if (!internals.isPasswordValid(password)) {
        throw Boom.badRequest('Password does not meet minimum requirements');
    }

    const salt = Crypto.randomBytes(128).toString('base64');
    const hash = await internals.createHash(password, salt);

    return {
        hash,
        salt
    };
};

module.exports = {
    'verify': internals.verifyPassword,
    'create': internals.hashPassword
};
