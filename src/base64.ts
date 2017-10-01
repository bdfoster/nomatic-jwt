import * as Crypto from 'crypto-js';

export function encode(data: string | Buffer = ''): string {
    if (data instanceof Buffer) {
        data = data.toString();
    }

    return Crypto.enc.Base64.stringify(Crypto.enc.Utf8.parse(data));
}

export function escape(data: string) {
    return data.replace(/=+$/, '').replace(/\//g, '_').replace(/\+/g, '-');
}

export function unescape(data: string) {
    return data.replace(/_/g, '/').replace(/-/g, '+');
}

export function encodeSafe(data: string | Buffer = ''): string {
   return escape(encode(data));
}

export function decode (data: string = ''): string {
    return Crypto.enc.Base64.parse(data).toString(Crypto.enc.Utf8);
}

export function decodeSafe(data: string = ''): string {
    return unescape(decode(data));
}
