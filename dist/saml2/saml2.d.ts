/// <reference types="lodash" />
import { SignedXml } from 'xml-crypto';
export declare type Callback<T> = (error?: Error | null, result?: T) => void;
export interface SelectedValue {
    toLocaleString: () => string;
    toString: () => string;
    valueOf: () => string | number | boolean | Object;
}
export interface ResponseHeader {
    version: string;
    destination: string;
    in_response_to: string;
    id: string;
}
export declare const XMLNS: {
    SAML: string;
    SAMLP: string;
    MD: string;
    DS: string;
    XENC: string;
    EXC_C14N: string;
};
export declare const create_authn_request: (issuer: string, assert_endpoint: string, destination: string, force_authn: boolean, context?: any, nameid_format?: string) => {
    xml: string;
    id: string;
};
export declare const sign_authn_request: (xml: string, private_key: string, options: any) => string;
export declare const extract_certificate_data: (certificate: string) => string;
export declare const certificate_to_keyinfo: (use: string, certificate: string) => {
    '@use': string;
    'ds:KeyInfo': {
        '@xmlns:ds': string;
        'ds:X509Data': {
            'ds:X509Certificate': string;
        };
    };
};
export declare const create_metadata: (entity_id: string, assert_endpoint: string, signing_certificates: string[], encryption_certificates: string[]) => string;
export declare const create_logout_request: (issuer: string, name_id: string, session_index: string, destination: string) => {
    id: string;
    xml: string;
};
export declare const create_logout_response: (issuer: string, in_response_to: string, destination: string, status?: string) => string;
export declare const format_pem: (key: string, type: string) => string;
export declare const sign_request: (saml_request: string, private_key: string, relay_state: any, response?: boolean) => any;
export declare const get_attribute_value: (node: Element, attributeName: string) => string;
export declare const check_status_success: (dom: Document) => boolean;
export declare const get_status: (dom: Document) => {
    [key: string]: string[];
};
export declare const to_error: (err: any) => Error | null;
export declare const decrypt_assertion: (dom: Document, private_keys: string[], cb: Callback<string>) => void;
export declare const get_signed_data: (doc: Document, sig: SignedXml) => any[];
export declare const check_saml_signature: (_xml: string, certificate: string) => any[] | null;
export declare const parse_response_header: (dom: Document) => ResponseHeader;
export declare const get_name_id: (dom: any) => any;
export declare const get_session_info: (dom: Document, index_required?: boolean) => {
    index: string;
    not_on_or_after: string;
};
export declare const parse_assertion_attributes: (dom: Document) => {
    [key: string]: string[];
};
export declare const pretty_assertion_attributes: (assertion_attributes: {
    [key: string]: any;
}) => import("lodash").Dictionary<any>;
export declare const add_namespaces_to_child_assertions: (xml_string: string) => string;
export declare const parse_authn_response: (saml_response: Document, sp_private_keys: string[], idp_certificates: string[], allow_unencrypted: boolean, ignore_signature: boolean, require_session_index: boolean, ignore_timing: boolean, notbefore_skew: number, sp_audience: string, cb: any) => void;
export declare const parse_logout_request: (dom: Document) => Partial<{
    issuer: string;
    name_id: string;
    session_index: string;
}>;
export declare const set_option_defaults: (request_options: any, idp_options: any, sp_options: any) => any;
