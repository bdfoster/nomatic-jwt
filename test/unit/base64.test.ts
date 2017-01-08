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

        it('should encode a Buffer to base64', () => {
            expect(base64.encode(new Buffer(decodedString))).to.equal(encodedString);
        });

        it('should encode a blank string to base64', () => {
            expect(base64.encode()).to.equal('');
        });
    });

    describe('#encodeSafe()', () => {
        it('should encode a UTF-8 string to base 64, URL Safe', () => {
            expect(base64.encodeSafe(decodedString)).to.equal(encodedStringSafe);
        });

        it('should encode a blank string to base64', () => {
            expect(base64.encodeSafe()).to.equal('');
        });
    });

    describe('#decode()', () => {
        it ('should decode a base 64 string to UTF-8', () => {
            expect(base64.decode(encodedString)).to.equal(decodedString);
        });

        it('should decode a blank string to base64', () => {
            expect(base64.decode()).to.equal('');
        });
    });

    describe('#decodeSafe()', () => {
        it('should decode a URL-safe base 64 string to UTF-8', () => {
            expect(base64.decodeSafe(encodedStringSafe)).to.equal(decodedString);
        });

        it('should decode a blank string to base64', () => {
            expect(base64.decodeSafe()).to.equal('');
        });
    });
});