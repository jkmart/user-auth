'use strict';

const Boom = require('boom');
const { verify, create } = require('./hash');

// Declare internals
const internals = {};

/**
 * Verify a password with a given hash and salt
 *
 * @param {string} password
 * @param {{hash: string, salt: string}}
 * @return {Promise} user
 */
internals.authenticateUser = async (password, { hash, salt }) => {

    if (!password) {
        throw Boom.badRequest('Missing password');
    }

    if (!(hash && salt)) {
        throw Boom.badRequest('Hash and salt are required');
    }

    return await verify(password, hash, salt);
};

/**
 * Generate a hash and salt for a given password
 *
 * @param {string} password
 * @return {Promise<{hash: string, salt: string}>}
 */
internals.hashPassword = async (password) => {

    if (!password) {
        throw Boom.badRequest('Invalid password');
    }

    return await create(password);
};

module.exports = {
    'authenticate': internals.authenticateUser,
    'generate': internals.hashPassword
};
