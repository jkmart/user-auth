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
 * @param {string} user.pass
 * @param {string} user.salt
 * @return {Promise} user
 */
internals.authenticateUser = async (password, user) => {

  if (!(password && user)) {
    throw Boom.badRequest('Invalid password or user');
  }

  return Auth.verify(password, user.pass, user.salt);
};

/**
 * Generate a hash and salt for a given password
 *
 * @param {string} password
 * @param {Object} user
 * @return {Promise} user
 */
internals.updatePassword = async (password, user) => {

  if (!(password && user)) {
    throw Boom.badRequest('Invalid password or user');
  }

  const {hash, salt} = await Auth.hash(password);
  user.pass = hash;
  user.salt = salt;

  return user;
};

module.exports = {
  'authenticate': internals.authenticateUser,
  'update': internals.updatePassword
};
