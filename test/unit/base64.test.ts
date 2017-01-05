import {expect} from 'chai';
import 'mocha';
import * as base64 from '../../lib/base64';


describe('base64', () => {
    const decodedString = 'abcdefg< > # % { } | \ ^ ~ [ ] `\'';
    const encodedString = 'YWJjZGVmZzwgPiAjICUgeyB9IHwgIF4gfiBbIF0gYCc=';
    const encodedStringSafe = 'YWJjZGVmZzwgPiAjICUgeyB9IHwgIF4gfiBbIF0gYCc';

    describe('#encode()', () => {
        it('should encode a UTF-8 string to base 64', () => {
            expect(base64.encode(decodedString)).to.equal(encodedString);
        });
    });

    describe('#encodeSafe()', () => {
        it('should encode a UTF-8 string to base 64, URL Safe', () => {
            expect(base64.encodeSafe(decodedString)).to.equal(encodedStringSafe);
        });
    });

    describe('#decode()', () => {
        it ('should decode a base 64 string to UTF-8', () => {
            expect(base64.decode(encodedString)).to.equal(decodedString);
        });
    });

    describe('#decodeSafe()', () => {
        it('should decode a URL-safe base 64 string to UTF-8', () => {
            expect(base64.decodeSafe(encodedStringSafe)).to.equal(decodedString);
        });
    });
});