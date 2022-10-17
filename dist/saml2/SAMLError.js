"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SAMLError = void 0;
class SAMLError extends Error {
    constructor(message, extra) {
        super(message);
        this.message = message;
        this.extra = extra;
    }
}
exports.SAMLError = SAMLError;
