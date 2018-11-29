'use strict';

const StateMachine = require('javascript-state-machine');

// Declare internals
const internals = {};

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

module.exports = {
    'validate': internals.isPasswordValid
};
