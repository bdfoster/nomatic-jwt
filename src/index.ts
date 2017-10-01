import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';
import * as base64 from './base64';
import {JWTError, JWTExpiredError, JWTSignatureError} from './errors';

export type JWTAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
export type JWTClaims = JWTRegisteredClaims & JWTPrivateClaims;
export type JWTPayloadData = JWTClaims | string;

export interface JWTHeaderData {
    typ: string;
    alg: string;
}

export interface JWTOptions {
    algorithm?: JWTAlgorithm;
    autoValidate?: boolean;
    expiresIn?: number; // In seconds
    timeOffset?: number; // In seconds
    key?: string;
    privateKey?: string;
    publicKey?: string;
}

export interface JWTData {
    header: JWTHeaderData;
    payload: JWTPayloadData;
    signature: string;
}

export interface JWTRegisteredClaims {
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

export interface JWTPrivateClaims {
    [key: string]: string | number | boolean | Object | any[];
}

export class JWT {
    private _algorithm: JWTAlgorithm;
    private _autoValidate: boolean;
    private _expiresIn: number;
    private _key: string;
    private _privateKey: string;
    private _publicKey: string;
    private _timeOffset: number;


    constructor (options: JWTOptions = {}) {
        this.algorithm = options.algorithm || 'HS256';
        this.expiresIn = options.expiresIn || (60 * 60);

        this.autoValidate = options.autoValidate || true;

        if (this.algorithm.startsWith('HS')) {
            this.key = options.key || crypto.randomBytes(128).toString('hex');
        } else if (options.privateKey && options.publicKey) {
            this.privateKey = options.privateKey;
            this.publicKey = options.publicKey;
        } else {
            throw new JWTError(`'privateKey' and 'publicKey' must be specified with ${this.algorithm} algorithm`);
        }

        this.timeOffset = options.timeOffset || 60;
    }

    public static parsePayload(payload: string): JWTPayloadData {
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

    public get algorithm() {
        return this._algorithm;
    }

    public set algorithm(algorithm: JWTAlgorithm) {
        if (algorithm.startsWith('HS') || algorithm.startsWith('RS')) {
            if (algorithm.endsWith('256') || algorithm.endsWith('384') || algorithm.endsWith('512')) {
                this._algorithm = algorithm;
                return;
            }
        }

        throw new JWTError(`Invalid algorithm: ${algorithm}`);
    }

    public get autoValidate() {
        return this._autoValidate;
    }

    public set autoValidate(autoValidate: boolean) {
        this._autoValidate = autoValidate;
    }

    public get expiresIn() {
        return this._expiresIn;
    }

    public set expiresIn(expiresIn: number) {
        if (typeof expiresIn === 'number') {
            this._expiresIn = expiresIn;
            return;
        }

        throw new JWTError('\'expiresIn\' must be a number');
    }

    public get key() {
        return this._key;
    }

    public set key(key: string) {
        if (typeof key === 'string') {
            this._key = key;
            return;
        }

        throw new JWTError('\'key\' must be a string');
    }

    public get privateKey() {
        return this._privateKey;
    }

    public set privateKey(privateKey: string) {
        if (typeof privateKey === 'string') {
            this._privateKey = privateKey;
            return;
        }

        throw new JWTError('\'privateKey\' must be a string');
    }

    public get publicKey() {
        return this._publicKey;
    }

    public set publicKey(publicKey: string) {
        if (typeof publicKey === 'string') {
            this._publicKey = publicKey;
            return;
        }

        throw new JWTError('\'publicKey\' must be a string');
    }

    public get timeOffset() {
        return this._timeOffset;
    }

    public set timeOffset(timeOffset: number) {
        if (typeof timeOffset === 'number') {
            this._timeOffset = timeOffset;
            return;
        }

        throw new JWTError('\'timeOffset\' must be a number');
    }

    public signRaw(data: string, key: string = null, algorithm: JWTAlgorithm = this.algorithm): string {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.privateKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.key;
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

    public verifyRaw(data: string, signature: string, key: string = null, algorithm: JWTAlgorithm = this.algorithm): boolean {
        if (algorithm.startsWith('HS')) {
            if (!key) {
                key = this.key;
            }

            return signature === this.signRaw(data, key, algorithm);
        } else if (algorithm.startsWith('RS')) {
            if (!key) {
                key = this.publicKey;
            }

            return crypto.createVerify('RSA-SHA' + algorithm.substr(2))
                .update(data)
                .verify(key, base64.unescape(signature), 'base64');
        } else {
            throw new Error('Unknown or unsupported algorithm: ' + algorithm);
        }
    }

    public decode(encoded: string, key: string = null, algorithm: JWTAlgorithm = this.algorithm): JWTData {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.publicKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.key;
            }
        }

        const encodedParts = encoded.split('.');

        if (encodedParts.length !== 3) {
            throw new Error('Invalid number of encoded parts: ' + encoded.length);
        }

        const token: JWTData = {
            header: JSON.parse(base64.decodeSafe(encodedParts[0])),
            payload: JWT.parsePayload(base64.decodeSafe(encodedParts[1])),
            signature: encodedParts[2]
        };

        if (this.autoValidate) {
            return this.validate(token, key, algorithm);
        } else {
            return token;
        }
    }

    public encode(payload: JWTPayloadData, key: string = null, algorithm: JWTAlgorithm = this.algorithm): string {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.privateKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.key;
            }
        }

        const header: JWTHeaderData = {
            typ: 'JWT',
            alg: algorithm
        };

        if (this.expiresIn && !(payload instanceof String) && !payload.exp) {
            const current = Math.floor(( new Date().getTime() / 1000));
            payload.exp = current + this.expiresIn;

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

    public validate(token: JWTData, key: string = null, algorithm: JWTAlgorithm = this.algorithm): JWTData {
        if (!key) {
            if (algorithm.startsWith('RS')) {
                key = this.publicKey;
            } else if (algorithm.startsWith('HS')) {
                key = this.key;
            }
        }

        const encoded = [];

        encoded.push(base64.encodeSafe(JSON.stringify(token.header)));
        encoded.push(base64.encodeSafe(JSON.stringify(token.payload)));

        const data = encoded.join('.');

        if (!(this.verifyRaw(data, token.signature, key, algorithm))) {
            throw new JWTSignatureError();
        }

        if (!(token.payload instanceof String)) {
            // `this.timeOffset`, `token.payload['nbf']` (not before) and `token.payload['exp']` (expires) are in seconds
            if (token.payload['nbf']) {
                const current = Math.floor((Date.now() / 1000));
                if (current > (token.payload['nbf'] + this.timeOffset)) {
                    throw new JWTError('JWT is not active yet');
                }
            }

            if (token.payload['exp']) {
                const current = Math.floor((Date.now() / 1000));

                if (current + this.timeOffset > token.payload['exp']) {
                    throw new JWTExpiredError(token.payload['exp']);
                }
            }
        }

        return token;
    }
}

/**
 * @module nomatic-jwt
 */
export default new JWT();
