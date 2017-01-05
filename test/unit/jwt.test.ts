import {expect} from 'chai';
import 'mocha';
import * as jwt from '../../lib/jwt';


describe('JWT', () => {
    let hmac: jwt.JWT;
    before((done) => {
        hmac = new jwt.JWT({
            algorithm: 'HS256',
            expiresIn: 60 * 60,
            key: 'testkey12341234',
            timeOffset: 60,
            validate: false
        });
        return done();
    });

    describe('#constructor()', () => {
        it('should create a new instance', () => {
            expect(jwt.default).to.not.be.undefined;

            expect(jwt.default).to.have.keys([
                'options'
            ]);

            expect(jwt.default.options).to.have.keys([
                'algorithm',
                'expiresIn',
                'key',
                'timeOffset',
                'validate'
            ]);

            expect(jwt.default.options.key.length).to.not.equal(0);
        });
    });

    describe('#sign()', () => {
        it('should consistently sign some data via HMAC', () => {
            const data = JSON.stringify({
                bool: true,
                str: 'test123',
                num: 123
            });
            const comparison = hmac.sign(data);

            expect(comparison).to.equal(hmac.sign(data));
        });
    });

    describe('#encode()', () => {
        it('should encode a token', () => {
            const token = hmac.encode({
                data: true
            });

            expect(token.split('.').length).to.equal(3);
        });
    });

    describe('#decode()', () => {
        it('should decode a token', () => {
            const data = {
                bool: true,
                str: 'test123',
                num: 123
            };
            const token = hmac.encode(data);

            const decoded = hmac.decode(token);

            expect(decoded.payload).to.equal(JSON.stringify(data));
        });
    });

    describe('#validate()', () => {
        it('should validate a token', () => {
            const data = {
                bool: true,
                str: 'test123',
                num: 123
            };
            const token = hmac.encode(data);

            const decoded = hmac.validate(token);

            expect(decoded.payload).to.equal(JSON.stringify(data));
        });
    });
});