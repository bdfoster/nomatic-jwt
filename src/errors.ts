export class JWTError extends Error {
    public statusCode: number = 400;

    constructor(message: string) {
        super(message);
    }
}

export class JWTExpiredError extends JWTError {
    public expiredAt: number;

    constructor(expiredAt: number) {
        super('JWT has already expired');
        this.expiredAt = expiredAt;
    }
}

export class JWTSignatureError extends JWTError {
    constructor() {
        super('JWT signature is not valid');
    }
}


