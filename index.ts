import * as crypto from 'crypto';
import * as base64 from './lib/base64';

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256';
export type Payload = Object | string;

export interface Header {
    typ?: string;
    alg?: string;
}

export interface DecodeOptions {
    algorithm?: Algorithm;
    validate?: boolean;
}

export interface EncodeOptions {
    header?: Header;
    algorithm?: Algorithm;
    // In seconds
    expiresIn?: number;
}

export interface SignOptions {
    algorithm?: Algorithm;
}

export interface ValidateOptions {
    algorithm?: Algorithm;
    // In seconds
    timeOffset?: number;
}

export interface DefaultOptions {
    decode?: DecodeOptions;
    encode?: EncodeOptions;
    sign?: SignOptions;
    validate?: ValidateOptions;
}

export interface Token {
    header: Header;
    payload: Object | string;
    signature: string;
}

export class JWT {
    public options: DefaultOptions;
    private key: string;
    private algorithm: Algorithm;

    constructor (key: string, algorithm: Algorithm, options: DefaultOptions = {}) {
        this.options = options;
        this.key = key;
        this.algorithm = algorithm;
    }

    public sign(data: string, options: SignOptions = null): string {
        if (options && this.options.sign) {
            options = Object.assign(this.options.sign, options);
        } else {
            options = this.options.sign;
        }

        if (!options.algorithm) {
            options.algorithm = this.algorithm;
        }

        let signature: string;

        if (options.algorithm === 'RS256') {
            signature = crypto.createSign('RSA-SHA' + options.algorithm.substr(1))
                .update(data)
                .sign(this.key, 'hex');

        } else if (options.algorithm === ('HS256' || 'HS384' || 'HS512')) {
            signature = crypto.createHmac('sha' + options.algorithm.substr(1), this.key)
                .update(data)
                .digest('hex');
        } else {
            throw new Error('Unknown or unsupported algorithm: ' + options.algorithm);
        }

        return base64.encodeSafe(signature);
    }

    public decode(encoded: string, options: DecodeOptions = null): Token {
        if (options && this.options.encode) {
            options = Object.assign(this.options.encode, options);
        } else {
            options = this.options.validate;
        }

        if (!options.algorithm) {
            options.algorithm = this.algorithm;
        }

        const encodedParts = encoded.split('.');

        if (encodedParts.length !== 3) {
            throw new Error('Invalid number of encoded parts: ' + encoded.length);
        }

        const token: Token = {
            header: base64.decodeSafe(encodedParts[0]),
            payload: base64.decodeSafe(encodedParts[1]),
            signature: encodedParts[2]
        };

        if (options.validate) {
            return this.validate(token);
        } else {
            return token;
        }
    }

    public encode(payload: Payload, options: EncodeOptions = null): string {
        if (options && this.options.encode) {
            options = Object.assign(this.options.encode, options);
        } else {
            options = this.options.encode;
        }

        if (!options.algorithm) {
            options.algorithm = this.algorithm;
        }

        let header = {
            typ: 'JWT',
            alg: options.algorithm
        };

        if (options.header) {
            header = Object.assign(header, options.header);
        }

        if (payload instanceof Object && options.expiresIn) {
            payload['exp'] = Date.now() / 1000 + options.expiresIn;
        }

        const encoded = [];

        encoded.push(base64.encodeSafe(JSON.stringify(header)));
        encoded.push(base64.encodeSafe(JSON.stringify(payload)));
        encoded.push(this.sign(encoded.join('.'), options.algorithm));

        return encoded.join('.');
    }

    public validate(data: string | Token, options: ValidateOptions = null) {
        if (options && this.options.validate) {
            options = Object.assign(this.options.validate, options);
        } else {
            options = this.options.validate;
        }

        if (!options.algorithm) {
            options.algorithm = this.algorithm;
        }

        let token: Token;

        if (data instanceof String) {
            token = this.decode(data);
        } else {
            token = data;
        }

        if (token.signature !== this.sign([token.header, token.payload].join('.'), options.algorithm)) {
            throw new Error('Signature validation failed');
        }

        if (!options.timeOffset) {
            options.timeOffset = 0;
        }

        // `options.timeOffset`, `token.payload['nbf']` (not before) and `token.payload['exp']` (expires) are in seconds
        if (token.payload['nbf'] && (Date.now() / 1000) - options.timeOffset < token.payload['nbf']) {
            throw new Error('Token is not active yet');
        }

        if (token.payload['exp'] && (Date.now() / 1000) + options.timeOffset > token.payload['exp']) {
            throw new Error('Token has expired');
        }

        return token;
    }
}

export default new JWT(crypto.randomBytes(36).toString('hex'), 'HS256', {
    decode: {
        validate: true
    },
    encode: {
        expiresIn: 60 * 60 // 1 hour
    },
    validate: {
        timeOffset: 5 // 5 seconds
    }
});
