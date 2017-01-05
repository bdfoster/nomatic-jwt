export function encode(data: string | Buffer = ''): string {
    if (data instanceof Buffer) {
        return data.toString('base64');
    }

    return new Buffer(data).toString('base64');

}

export function encodeSafe(data: string | Buffer = '') {
    data = encode(data);
    return data.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decode (data: string | Buffer = '') {
    if (data instanceof Buffer) {
        return data.toString('utf8');
    }

    return new Buffer(data, 'base64').toString('utf8');
}

export function decodeSafe(data: string | Buffer = '') {
    data = data.replace(/-/g, '+').replace(/_/g, '/');

    while (data.length % 4) {
        data += '=';
    }

    return decode(data);
}
