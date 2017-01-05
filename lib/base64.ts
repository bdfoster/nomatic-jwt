export function encode(data: string = '') {
    return new Buffer(data).toString('base64');
}

export function encodeSafe(data: string = '') {
    data = encode(data);
    return data.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decode (data: string = '') {
    return new Buffer(data, 'base64').toString('utf8');
}

export function decodeSafe(data: string = '') {
    data = data.replace(/-/g, '+').replace(/_/g, '/');

    while (data.length % 4) {
        data += '=';
    }

    return decode(data);
}
