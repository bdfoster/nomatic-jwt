# nomatic-jwt
[![Semantic Release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![GitHub release](https://img.shields.io/github/release/bdfoster/nomatic-jwt.svg)](https://github.com/bdfoster/nomatic-jwt/releases)
[![npm](https://img.shields.io/npm/v/nomatic-jwt.svg)](https://www.npmjs.com/package/nomatic-jwt)
[![Build Status](https://travis-ci.org/bdfoster/nomatic-jwt.svg?branch=greenkeeper%2Finitial)](https://travis-ci.org/bdfoster/nomatic-jwt)
[![Coverage Status](https://coveralls.io/repos/github/bdfoster/nomatic-jwt/badge.svg)](https://coveralls.io/github/bdfoster/nomatic-jwt)
[![dependencies Status](https://david-dm.org/bdfoster/nomatic-jwt/status.svg)](https://david-dm.org/bdfoster/nomatic-jwt)
[![devDependencies Status](https://david-dm.org/bdfoster/nomatic-jwt/dev-status.svg)](https://david-dm.org/bdfoster/nomatic-jwt?type=dev)
[![License](https://img.shields.io/github/license/bdfoster/nomatic-jwt.svg)](https://github.com/bdfoster/nomatic-jwt/blob/master/LICENSE)

An opinionated library for encoding, decoding, and verifying JSON Web Tokens (JWTs), heavily inspired by 
[node-jwt-simple](https://github.com/hokaccha/node-jwt-simple).

### Installation
You can install from [npm](https://npmjs.com/nomatic-jwt) by doing:
```bash
npm i --save nomatic-jwt
```

### Basic Usage
```javascript
const JWT = require('nomatic-jwt').JWT;

const jwt = new JWT({
    algorithm: 'HS256', // "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512"
    expiresIn: 60 * 60, // 1hr
    key: 'somethingMoreSecureThanThis', // Valid only with HMAC-SHA algorithms
    timeOffset: 60, // allowable wiggle room for expiration (`exp`) and not valid before (`nbf`) claims
    validate: true // If false, won't validate when decoding
});

// Encode
const token = jwt.encode({
    sub: 'user/12345678',
    roles: ['manager']
});
/* eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
 * .eyJzdWIiOiJ1c2VyLzEyMzQ1Njc4Iiwicm9sZXMiOlsibWFuYWdlciJdLCJleHAiOjE1MDY4Nzk1ODAsIm5iZiI6MTUwNjg3NTk4MCwiaWF0IjoxNTA
 * 2ODc1OTgwfQ
 * .FjHYltcA1Natf6Iu72HyGxkk4GX2phMRG3yNW65_IsQ'
 */


// Decode
const decoded = jwt.decode(token);

```



