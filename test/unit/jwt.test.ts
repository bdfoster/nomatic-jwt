import {expect} from 'chai';
import 'mocha';
import * as jwt from '../../lib/jwt';


describe('JWT', () => {
    let instance: jwt.JWT;
    before((done) => {
        instance = new jwt.JWT({
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

    describe('#encode()', () => {
        it('should encode a token', () => {
            const token = instance.encode({
                data: true
            });

            expect(token.split('.').length).to.equal(3);
        });
    });

    describe('#decode()', () => {
        it('should decode a token', () => {
            const token = instance.encode({
                data: true
            });

            const decoded = instance.decode(token);

            expect(decoded.payload['data']).to.equal(true);
        });
    });

    describe('#validate()', () => {
        it('should validate a token', () => {
            const token = instance.encode({
                data: true
            });

            const decoded = instance.decode(token);

            expect(decoded.payload['data']).to.equal(true);
        });
    });
});