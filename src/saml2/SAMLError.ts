export class SAMLError extends Error {
    constructor(public message: string, public extra?: any) {
        super(message);
    }
}
