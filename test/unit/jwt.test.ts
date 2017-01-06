import {expect} from 'chai';
import 'mocha';
import * as jwt from '../../lib/jwt';
import {Token} from '../../lib/jwt';
import {Payload} from '../../lib/jwt';


describe('JWT', () => {
    let hmac: jwt.JWT;
    const decodedPayload = {
        bool: true,
        str: 'test123',
        num: 123
    };

    before((done) => {
        hmac = new jwt.JWT({
            algorithm: 'HS256',
            expiresIn: 60 * 60,
            key: 'testsecret123',
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

    describe('#signRaw()', () => {
        it('should consistently sign some data via HMAC', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = hmac.signRaw(data);
            expect(signature).to.deep.equal(hmac.signRaw(data));
        });
    });

    describe('#verifyRaw()', () => {
        it('should verify signature of data via HMAC', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = hmac.signRaw(data).toString();
            expect(hmac.verifyRaw(data, signature)).to.equal(true);
        });
    });

    describe('#encode()', () => {
        it('should encode a token', () => {
            const token = hmac.encode(decodedPayload);
            expect(token.split('.').length).to.equal(3);
        });
    });

    describe('#decode()', () => {
        it('should decode a token', () => {
            const token = hmac.encode(decodedPayload);
            const decoded = hmac.decode(token);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });
    });

    describe('#validate()', () => {
        it('should validate a token', () => {
            const encoded = hmac.encode(decodedPayload);
            console.log(encoded);
            const decoded: Token = hmac.decode(encoded);
            hmac.validate(decoded);
            const payload: Payload = decoded.payload;
            expect(payload['exp']).to.equal(payload['iat'] + hmac.options.expiresIn);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });
    });
});