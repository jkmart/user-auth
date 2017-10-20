'use strict';

const Promise = require('bluebird');
const Boom = require('boom');
const Auth = require('../auth');

/**
 * Verify a password with a given hash and salt
 *
 * @param {string} password
 * @param {Object} user
 * @param {string} user.pass
 * @param {string} user.salt
 * @return {Promise} user
 */
function authenticateUser(password, user) {

  if (!(password && user)) {
    return Promise.reject(Boom.badRequest('Invalid password or user'));
  }

  return Auth.verify(password, user.pass, user.salt);
}

/**
 * Generate a hash and salt for a given password
 *
 * @param {string} password
 * @param {Object} user
 * @return {Promise} user
 */
function updatePassword(password, user) {

  if (!(password && user)) {
    return Promise.reject(Boom.badRequest('Invalid password or user'));
  }
  return Auth.hash(password)
    .then((result) => {
      user.pass = result.hash;
      user.salt = result.salt;
      return Promise.resolve(user);
    });

}

module.exports = {
  'update': updatePassword,
  'verify': authenticateUser
};
