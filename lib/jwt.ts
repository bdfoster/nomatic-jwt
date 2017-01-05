import * as crypto from 'crypto';
import * as base64 from './base64';
import {TokenExpiredError, TokenSignatureValidationError} from './errors';

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256';
export type Payload = Claims | string;

export interface Header {
    typ: string;
    alg: string;
}

export interface DefaultOptions {
    algorithm: Algorithm;
    expiresIn?: number; // In seconds
    timeOffset?: number; // In seconds
    key: string;
    validate?: boolean;
}

export interface Token {
    header: Header;
    payload: Payload;
    signature: string;
}

export interface Claims {
    /**
     * Issuer (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.1)
     */
    iss?: any;

    /**
     * Subject (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.2)
     */
    sub?: any;

    /**
     * Audience (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.3)
     */
    aud?: any;

    /**
     * Expiration Time (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.4)
     */
    exp?: number;

    /**
     * Not Before (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.5)
     */
    nbf?: number;

    /**
     * Issued At (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.6)
     */
    iat?: number; // In seconds

    /**
     * JWT ID (registered): RFC-7519 (https://tools.ietf.org/html/rfc7519#section-4.1.7)
     */
    jid?: any;
}

export class JWT {
    protected options: DefaultOptions;

    constructor (options: DefaultOptions) {
        this.options = options;

        if (!this.options.timeOffset) {
            this.options.timeOffset = 0;
        }
    }

    public sign(data: string, algorithm: Algorithm = this.options.algorithm, key: string = this.options.key): string {

        let signature: Buffer;

        if (algorithm === 'RS256') {
            signature = crypto.createSign('RSA-SHA' + algorithm.substr(1))
                .update(data)
                .sign(key);

        } else if (algorithm === ('HS256' || 'HS384' || 'HS512')) {
            signature = crypto.createHmac('sha' + algorithm.substr(1), key)
                .update(data)
                .digest();
        } else {
            throw new Error('Unknown or unsupported algorithm: ' + algorithm);
        }

        return base64.encodeSafe(signature);
    }

    public decode(encoded: string, algorithm: Algorithm = this.options.algorithm, key: string = this.options.key): Token {
        const encodedParts = encoded.split('.');

        if (encodedParts.length !== 3) {
            throw new Error('Invalid number of encoded parts: ' + encoded.length);
        }

        const token: Token = {
            header: JSON.parse(base64.decodeSafe(encodedParts[0])),
            payload: base64.decodeSafe(encodedParts[1]),
            signature: encodedParts[2]
        };



        if (this.options.validate) {
            return this.validate(token, algorithm, key);
        } else {
            return token;
        }
    }

    public encode(payload: Payload, algorithm: Algorithm = this.options.algorithm, key: string = this.options.key): string {

        const header: Header = {
            typ: 'JWT',
            alg: algorithm
        };

        if (payload instanceof Object && this.options.expiresIn) {
            payload['exp'] = Date.now() / 1000 + this.options.expiresIn;
        }

        const encoded = [];

        encoded.push(base64.encodeSafe(JSON.stringify(header)));
        encoded.push(base64.encodeSafe(JSON.stringify(payload)));
        encoded.push(this.sign(encoded.join('.'), algorithm, key));

        return encoded.join('.');
    }

    public validate(data: string | Token, algorithm: Algorithm = this.options.algorithm, key: string = this.options.key) {

        let token: Token;

        if (data instanceof String) {
            token = this.decode(data);
        } else {
            token = data;
        }

        if (token.signature !== this.sign([token.header, token.payload].join('.'), algorithm, key)) {
            throw new TokenSignatureValidationError();
        }

        // `options.timeOffset`, `token.payload['nbf']` (not before) and `token.payload['exp']` (expires) are in seconds
        if (token.payload['nbf'] && (Date.now() / 1000) - this.options.timeOffset < token.payload['nbf']) {
            throw new Error('Token is not active yet');
        }

        if (token.payload['exp'] && (Date.now() / 1000) + this.options.timeOffset > token.payload['exp']) {
            throw new TokenExpiredError(token.payload['exp']);
        }

        return token;
    }
}

export default new JWT({
    algorithm: 'HS256',
    expiresIn: 60 * 60,
    key: crypto.randomBytes(32).toString('utf8'),
    timeOffset: 60,
    validate: true
});
