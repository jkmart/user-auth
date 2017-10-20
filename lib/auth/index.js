'use strict';

const Boom = require('boom');
const Buffer = require('buffer').Buffer;
const Crypto = require('crypto');
const Promisify = require('util').promisify;
const StateMachine = require('javascript-state-machine');

// Declare internals
const internals = {
  encrypt: Promisify(Crypto.pbkdf2)
};

internals.passwordStates = [
  {
    name: 'validate',
    from: 'noneValid',
    to: 'oneValid'
  },
  {
    name: 'validate',
    from: 'oneValid',
    to: 'twoValid'
  },
  {
    name: 'validate',
    from: 'twoValid',
    to: 'threeValid'
  },
  {
    name: 'validate',
    from: 'threeValid',
    to: 'threeValid'
  },
  {
    name: 'reset',
    from: '*',
    to: 'noneValid'
  }
];

internals.minimumLength = 6;
internals.lowercaseCharacter = /[a-z]+?/;
internals.uppercaseCharacter = /[A-Z]+?/;
internals.numberCharacter = /[0-9]+?/;
internals.specialCharacter = /[\W]+?/;

internals.fsm = new StateMachine.create({
  initial: 'noneValid',
  events: internals.passwordStates
});

/**
 * Check if password meets all password criteria
 *
 * @param {string} password
 * @return {boolean}
 */
internals.isPasswordValid = (password) => {

  internals.fsm.reset();

  if (!password) {
    return false;
  }

  if (password.length < internals.minimumLength) {
    return false;
  }

  // lowercase character
  if (internals.lowercaseCharacter.test(password)) {
    internals.fsm.validate();
  }

  // uppercase character
  if (internals.uppercaseCharacter.test(password)) {
    internals.fsm.validate();
  }

  // number character
  if (internals.numberCharacter.test(password)) {
    internals.fsm.validate();
  }

  // special character
  if (internals.specialCharacter.test(password)) {
    internals.fsm.validate();
  }

  return internals.fsm.is('threeValid');
};

/**
 * Check a password using a salt and hash to verify
 *
 * @param {string} password
 * @param {string} hash
 * @param {string} salt
 * @return boolean
 */
internals.verifyPassword = async (password, hash, salt) => {

  const dk = await internals.encrypt(password, salt, 10000, 512, 'sha1');
  const key = new Buffer(dk, 'binary').toString('hex');

  return key === hash;
};

/**
 * Create new valid password hash with salt
 *
 * @param {string} password
 * @returns {hash, salt}
 */
internals.hashPassword = async (password) => {

  if (!internals.isPasswordValid(password)) {
    throw Boom.badRequest('Password does not meet minimum requirements');
  }

  const salt = Crypto.randomBytes(128).toString('base64');

  const dk = await internals.encrypt(password, salt, 10000, 512, 'sha1');
  const key = new Buffer(dk, 'binary').toString('hex');

  return {'hash': key, 'salt': salt};
};

module.exports = {
  'verify': internals.verifyPassword,
  'hash': internals.hashPassword
};
