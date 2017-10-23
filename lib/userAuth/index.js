'use strict';

const Boom = require('boom');
const Auth = require('../auth');

// Declare internals
const internals = {};

/**
 * Verify a password with a given hash and salt
 *
 * @param {string} password
 * @param {Object} user
 * @param {string} user.hash
 * @param {string} user.salt
 * @return {Promise} user
 */
internals.authenticateUser = async (password, user) => {

  if (!(password && user)) {
    throw Boom.badRequest('Invalid password or user');
  }

  return Auth.verify(password, user.hash, user.salt);
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

  return await Auth.hash(password);
};

module.exports = {
  'authenticate': internals.authenticateUser,
  'generate': internals.hashPassword
};
