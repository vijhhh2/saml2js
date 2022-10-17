/// <reference types="node" />
export interface ServiceProviderOptions {
    entity_id: string;
    private_key: string;
    certificate: string;
    assert_endpoint: string;
    alt_private_keys: string[];
    alt_certs: string[];
    audience?: string;
    notbefore_skew?: number;
    force_authn?: boolean;
}
export interface IdentityProviderOptions {
    certificates: string[];
    shared_options: {
        [key: string]: any;
    };
    options: {
        [key: string]: any;
    };
    sso_login_url: string;
    sso_logout_url: string;
}
export declare class ServiceProvider {
    entity_id: string;
    private_key: string;
    certificate: string;
    assert_endpoint: string;
    alt_private_keys: string[];
    alt_certs: string[];
    audience?: string;
    notbefore_skew?: number;
    shared_options: Partial<ServiceProviderOptions>;
    constructor(options: ServiceProviderOptions);
    create_login_request_url(identity_provider: IdentityProviderOptions, options: any, cb: any): void;
    create_authn_request_xml(identity_provider: IdentityProviderOptions, options: any): string;
    redirect_assert(identity_provider: IdentityProviderOptions, options: any, cb: any): void | NodeJS.Immediate;
    post_assert(identity_provider: IdentityProviderOptions, options: any, cb: any): void | NodeJS.Immediate;
    _assert(identity_provider: IdentityProviderOptions, options: any, cb: any): void | NodeJS.Immediate;
    create_logout_request_url(identity_provider: Partial<IdentityProviderOptions>, options: any, cb: any): void;
    create_logout_response_url(identity_provider: Partial<IdentityProviderOptions>, options: any, cb: any): void;
    create_metadata(): string;
}
export declare class IdentityProvider {
    sso_login_url: string;
    sso_logout_url: string;
    certificates: string[];
    shared_options: {
        [key: string]: any;
    };
    constructor(options: {
        sso_login_url: string;
        sso_logout_url: string;
        certificates: string | string[];
    });
}
