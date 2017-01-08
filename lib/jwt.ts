import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';
import * as base64 from './base64';
import {TokenExpiredError, TokenSignatureError} from './errors';

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
export type Claims = RegisteredClaims & PrivateClaims;
export type Payload = Claims | String;

export interface Header {
    typ: string;
    alg: string;
}

export interface Options {
    algorithm?: Algorithm;
    expiresIn?: number; // In seconds
    timeOffset?: number; // In seconds
    key?: string;
    privateKey?: string;
    publicKey?: string;
    validate?: boolean;
}

export interface Token {
    header: Header;
    payload: Payload;
    signature: string;
}

export interface RegisteredClaims {
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

export interface PrivateClaims {
    [key: string]: string | number | boolean | Object | Array<any>;
}

export class JWT {
    public options: Options;

    constructor (options: Options) {
        this.options = options;

        if (!this.options.timeOffset) {
            this.options.timeOffset = 0;
        }

        if (!this.options.algorithm) {
            this.options.algorithm = 'HS256';
        }

        if (this.options.algorithm.startsWith('HS') && !(this.options.key)) {
            throw new Error('Must specify `key` param with algorithm: ' +  this.options.algorithm);
        }

        if (this.options.algorithm.startsWith('RS') && (!(this.options.privateKey || this.options.publicKey))) {
            throw new Error('Must specify `privateKey` and `publicKey` with algorithm: ' + this.options.algorithm);
        }
    }

    public static parsePayload(payload: string): Payload {
        try {
            return JSON.parse(payload);
        } catch (error) {
            if (error.name !== 'SyntaxError') {
                throw error;
            } else {
                return payload;
            }
        }
    }

    public signRaw(data: string, key: string = null, algorithm: Algorithm = this.options.algorithm): string {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.options.privateKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.options.key;
            }
        }

        let signature: string;

        if (algorithm.startsWith('RS')) {
            signature = crypto.createSign('RSA-SHA' + algorithm.substr(2))
                .update(data)
                .sign(key, 'base64');

        } else if (algorithm.startsWith('HS')) {
            signature = CryptoJS
                    .enc
                    .Base64
                    .stringify(CryptoJS['HmacSHA' + algorithm.substr(2)](data, key));
        } else {
            throw new Error('Unknown or unsupported algorithm: ' + algorithm);
        }

        return base64.escape(signature);
    }

    public verifyRaw(data: string, signature: string, key: string = null, algorithm: Algorithm = this.options.algorithm): boolean {
        if (algorithm.startsWith('HS')) {
            if (!key) {
                key = this.options.key;
            }

            return signature === this.signRaw(data, key, algorithm);
        } else if (algorithm.startsWith('RS')) {
            if (!key) {
                key = this.options.publicKey;
            }

            return crypto.createVerify('RSA-SHA' + algorithm.substr(2))
                .update(data)
                .verify(key, base64.unescape(signature), 'base64');
        } else {
            throw new Error('Unknown or unsupported algorithm: ' + algorithm);
        }
    }

    public decode(encoded: string, key: string = null, algorithm: Algorithm = this.options.algorithm): Token {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.options.publicKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.options.key;
            }
        }

        const encodedParts = encoded.split('.');

        if (encodedParts.length !== 3) {
            throw new Error('Invalid number of encoded parts: ' + encoded.length);
        }

        const token: Token = {
            header: JSON.parse(base64.decodeSafe(encodedParts[0])),
            payload: JWT.parsePayload(base64.decodeSafe(encodedParts[1])),
            signature: encodedParts[2]
        };

        if (this.options.validate) {
            return this.validate(token, key, algorithm);
        } else {
            return token;
        }
    }

    public encode(payload: Payload, key: string = null, algorithm: Algorithm = this.options.algorithm): string {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.options.privateKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.options.key;
            }
        }

        const header: Header = {
            typ: 'JWT',
            alg: algorithm
        };

        if (this.options.expiresIn && !(payload instanceof String) && !payload.exp) {
            const current = Math.floor(( new Date().getTime() / 1000));
            payload.exp = current + this.options.expiresIn;

            if (!payload.nbf) {
                payload.nbf = current;
            }

            if (!payload.iat) {
                payload.iat = current;
            }
        }

        const encoded = [];

        encoded.push(base64.encodeSafe(JSON.stringify(header)));
        encoded.push(base64.encodeSafe(JSON.stringify(payload)));
        encoded.push(this.signRaw(encoded.join('.'), key, algorithm));

        return encoded.join('.');
    }

    public validate(token: Token, key: string = null, algorithm: Algorithm = this.options.algorithm): Token {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.options.publicKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.options.key;
            }
        }

        const encoded = [];

        encoded.push(base64.encodeSafe(JSON.stringify(token.header)));
        encoded.push(base64.encodeSafe(JSON.stringify(token.payload)));

        const data = encoded.join('.');

        if (!(this.verifyRaw(data, token.signature, key, algorithm))) {
            throw new TokenSignatureError();
        }

        if (!(token.payload instanceof String)) {
            // `options.timeOffset`, `token.payload['nbf']` (not before) and `token.payload['exp']` (expires) are in seconds
            if (token.payload['nbf']) {
                const current = Math.floor((Date.now() / 1000));
                if (current > (token.payload['nbf'] + this.options.timeOffset)) {
                    throw new Error('Token is not active yet');
                }
            }

            if (token.payload['exp']) {
                const current = Math.floor((Date.now() / 1000));

                if (current + this.options.timeOffset > token.payload['exp']) {
                    throw new TokenExpiredError(token.payload['exp']);
                }
            }
        }

        return token;
    }
}

export const global = new JWT({
    expiresIn: 60 * 60,
    key: crypto.randomBytes(128).toString('hex'),
    timeOffset: 60,
    validate: true
});

export default global;
