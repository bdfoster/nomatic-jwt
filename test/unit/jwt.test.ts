import {expect} from 'chai';
import * as fs from 'fs';
import 'mocha';
import * as path from 'path';
import * as jwt from '../../lib/jwt';
import {Token} from '../../lib/jwt';
import {Payload} from '../../lib/jwt';


describe('JWT', () => {
    let hs: jwt.JWT;
    let rs: jwt.JWT;
    const decodedPayload = {
        bool: true,
        str: 'test123',
        num: 123
    };

    before((done) => {
        hs = new jwt.JWT({
            algorithm: 'HS256',
            expiresIn: 60 * 60,
            key: 'testsecret123',
            timeOffset: 60,
            validate: false
        });

        rs = new jwt.JWT({
            algorithm: 'RS256',
            expiresIn: 60 * 60,
            privateKey: fs.readFileSync(path.resolve(__dirname, '../fixtures/rs-private.pem'), 'utf8'),
            publicKey: fs.readFileSync(path.resolve(__dirname, '../fixtures/rs-public.pem'), 'utf8'),
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
        it('should consistently sign some data via HS algorithm type', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = hs.signRaw(data);
            expect(signature).to.deep.equal(hs.signRaw(data));
        });

        it ('should consistently sign some data via RS algorithm type', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = rs.signRaw(data);
            expect(signature).to.deep.equal(rs.signRaw(data));
        });
    });

    describe('#verifyRaw()', () => {
        it('should verify signature of data via HS algorithm type', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = hs.signRaw(data).toString();
            expect(hs.verifyRaw(data, signature)).to.equal(true);
        });

        it('should verify signature of data via RSA', () => {
            const data = ['5ng7oh22SHCA5A5l30USV49IXZ1uR3b1', 'RxQVPmN2JlDz1yylBB02ZCKz4GRg5uFa'].join('.');
            const signature = rs.signRaw(data).toString();
            expect(rs.verifyRaw(data, signature)).to.equal(true);
        });
    });

    describe('#encode()', () => {
        it('should encode a token via HS algorithm type', () => {
            const token = hs.encode(decodedPayload);
            expect(token.split('.').length).to.equal(3);
        });

        it('should encode a token via RS algorithm type', () => {
            const token = rs.encode(decodedPayload);
            expect(token.split('.').length).to.equal(3);
        });
    });

    describe('#decode()', () => {
        it('should decode a token via HS algorithm type', () => {
            const token = hs.encode(decodedPayload);
            const decoded = hs.decode(token);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });

        it('should decode a token via RS algorithm type', () => {
            const token = rs.encode(decodedPayload);
            const decoded = rs.decode(token);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });
    });

    describe('#validate()', () => {
        it('should validate a token via HS algorithm type', () => {
            const encoded = hs.encode(decodedPayload);
            const decoded: Token = hs.decode(encoded);
            hs.validate(decoded);
            const payload: Payload = decoded.payload;
            expect(payload['exp']).to.equal(payload['iat'] + hs.options.expiresIn);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });

        it('should validate a token via RS algorithm type', () => {
            const encoded = rs.encode(decodedPayload);
            const decoded: Token = rs.decode(encoded);
            rs.validate(decoded);
            const payload: Payload = decoded.payload;
            expect(payload['exp']).to.equal(payload['iat'] + rs.options.expiresIn);
            expect(decoded.payload).to.deep.equal(decodedPayload);
        });
    });
});