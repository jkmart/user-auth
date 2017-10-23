[![Build Status](https://travis-ci.org/jkmart/user-auth.svg?branch=master)](https://travis-ci.org/jkmart/user-auth)
## Synopsis

Hashes and verifies passwords

## Usage

Promise based library used to create valid passwords for users which can be safely stored in the database
as a hash and corresponding salt. Valid passwords are defined as:
- At least six characters
- Match at least three of the following criteria
    - One uppercase letter
    - One lowercase letter
    - One number
    - One symbol

 
 Examples of valid passwords:
 
```
haPpy3
t1gg@r
H3R3$ME
```

Uses Crypto.pbkdf2 using SHA-1 hash and a 128-byte salt to generate a 512-byte key.

## Installation

Install npm packages

`npm install --save user-auth`

## Example

```javascript
var userAuth = require('user-auth');

userAuth.generate('haPpy3')
.then(function (user) {
  console.log('hash', user.hash, 'salt', user.salt); // long random strings
  return userAuth.authenticate('haPpy3', user)
})
.then(function (isValid) {
  console.log('Verified?', isValid); // true!
})
```
or
```javascript
const userAuth = require('user-auth');

async function example() {
  const {hash, salt} = await userAuth.generate('haPpy3');
  console.log('hash', hash, 'salt', salt); // long random strings
  const isAuthenticated = await userAuth.authenticate('haPpy3', {hash, salt});
  console.log('Verified?', isAuthenticated);// true!
}
```