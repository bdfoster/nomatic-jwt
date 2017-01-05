export class TokenError extends Error {
    public statusCode: number = 400;

    constructor(message: string) {
        super(message);
    }
}

export class TokenExpiredError extends TokenError {
    public expiredAt: number;

    constructor(expiredAt: number) {
        super('Token has already expired');
        this.expiredAt = expiredAt;
    }
}

export class TokenSignatureValidationError extends TokenError {
    constructor() {
        super('Token signature is not valid');
    }
}


