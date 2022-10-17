import { defaults, extend, isArray, isNumber, isString, pick } from 'lodash';
import { deflateRaw, inflateRaw } from 'zlib';
import { parse, UrlObject, format } from 'url';
import { waterfall } from 'async';
import debug from 'debug';
import { DOMParser } from '@xmldom/xmldom';

import {
    add_namespaces_to_child_assertions,
    Callback,
    check_status_success,
    create_authn_request,
    create_logout_request,
    create_logout_response,
    create_metadata,
    get_status,
    parse_authn_response,
    parse_logout_request,
    parse_response_header,
    ResponseHeader,
    set_option_defaults,
    sign_authn_request,
    sign_request,
    XMLNS,
} from './saml2';
import { SAMLError } from './SAMLError';

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
    // 'auth_context',
    // 'nameid_format',
    // 'sign_get_request',
    // 'allow_unencrypted_assertion',
}

export interface IdentityProviderOptions {
    certificates: string[];
    shared_options: { [key: string]: any };
    options: { [key: string]: any };
    sso_login_url: string;
    sso_logout_url: string;
}

export class ServiceProvider {
    entity_id: string;
    private_key: string;
    certificate: string;
    assert_endpoint: string;
    alt_private_keys: string[] = [];
    alt_certs: string[];
    audience?: string;
    notbefore_skew?: number;
    shared_options: Partial<ServiceProviderOptions>;
    // Initializes a service provider given the passed options.

    // @entity_id, @private_key, @assert_endpoint, @certificate, @alt_private_keys, @alt_certs can
    // only be set here and are used by exported functions.

    // Rest of options can be set/overwritten by the identity provider and/or at function call.
    constructor(options: ServiceProviderOptions) {
        ({
            entity_id: this.entity_id,
            private_key: this.private_key,
            certificate: this.certificate,
            assert_endpoint: this.assert_endpoint,
            alt_private_keys: this.alt_private_keys,
            alt_certs: this.alt_certs,
        } = options);

        if (options.audience == null) {
            options.audience = this.entity_id;
        }
        if (options.notbefore_skew == null) {
            options.notbefore_skew = 1;
        }
        this.alt_private_keys = [...(this.alt_private_keys || [])]
        this.alt_certs = [...(this.alt_certs || [])];
        this.shared_options = pick(
            options,
            'force_authn',
            'auth_context',
            'nameid_format',
            'sign_get_request',
            'allow_unencrypted_assertion',
            'audience',
            'notbefore_skew'
        );
    }

    // Returns:
    //   Redirect URL at which a user can login
    //   ID of the request
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_login_request_url(
        identity_provider: IdentityProviderOptions,
        options: any,
        cb: any
    ) {
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        const { id, xml } = create_authn_request(
            this.entity_id,
            this.assert_endpoint,
            identity_provider.sso_login_url,
            options.force_authn,
            options.auth_context,
            options.nameid_format
        );
        return deflateRaw(xml, (err, deflated) => {
            let uri: any;
            if (err !== null) {
                return cb(err);
            }
            try {
                uri = parse(identity_provider.sso_login_url, true);
            } catch (error) {
                return cb(error);
            }
            delete uri.search; // If you provide search and query search overrides query :/
            if (options.sign_get_request) {
                extend(
                    uri.query,
                    sign_request(
                        deflated.toString('base64'),
                        this.private_key,
                        options.relay_state
                    )
                );
            } else {
                uri.query.SAMLRequest = deflated.toString('base64');
                if (options.relay_state != null) {
                    uri.query.RelayState = options.relay_state;
                }
            }
            return cb(null, new URL(uri), id);
        });
    }

    // Returns:
    //   An xml string with an AuthnRequest with an embedded xml signature
    // Params:
    //   identity_provider
    //   options
    create_authn_request_xml(
        identity_provider: IdentityProviderOptions,
        options: any
    ) {
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        const { id, xml } = create_authn_request(
            this.entity_id,
            this.assert_endpoint,
            identity_provider.sso_login_url,
            options.force_authn,
            options.auth_context,
            options.nameid_format
        );
        return sign_authn_request(xml, this.private_key, options);
    }

    // Returns:
    //   An object containing the parsed response for a redirect assert.
    //   This type of assert inflates the response before parsing it.
    // Params:
    //   identity_provider
    //   options
    //   cb
    redirect_assert(
        identity_provider: IdentityProviderOptions,
        options: any,
        cb: any
    ) {
        options = defaults(
            extend(options, {
                get_request: true,
            }),
            {
                require_session_index: true,
            }
        );
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        return this._assert(identity_provider, options, cb);
    }

    // Returns:
    //   An object containing the parsed response for a post assert.
    // Params:
    //   identity_provider
    //   options
    //   cb
    post_assert(identity_provider: IdentityProviderOptions, options: any, cb: any) {
        options = defaults(
            extend(options, {
                get_request: false,
            }),
            {
                require_session_index: true,
            }
        );
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        return this._assert(identity_provider, options, cb);
    }

    // Private function, called by redirect and post assert to return a response to
    // corresponding assert.
    _assert(identity_provider: IdentityProviderOptions, options: any, cb: any) {
        if (
            !(
                options.request_body?.SAMLResponse ||
                options.request_body?.SAMLRequest
            )
        ) {
            return setImmediate(
                cb,
                new Error(
                    'Request body does not contain SAMLResponse or SAMLRequest.'
                )
            );
        }
        if (!isNumber(options.notbefore_skew)) {
            return setImmediate(
                cb,
                new Error(
                    'Configuration error: `notbefore_skew` must be a number'
                )
            );
        }
        let saml_response: Document | null = null;
        // todo: extract proper types instead of partial
        let response: Partial<{
            response_header: ResponseHeader;
            type: string;
            issuer: string;
            name_id: string;
            session_index: string;
        }> = {};
        return waterfall(
            [
                function (cb_wf: Callback<Buffer>) {
                    var raw;
                    raw = Buffer.from(
                        options.request_body.SAMLResponse ||
                            options.request_body.SAMLRequest,
                        'base64'
                    );
                    // Inflate response for redirect requests before parsing it.
                    if (options.get_request) {
                        return inflateRaw(raw, cb_wf);
                    }
                    return setImmediate(cb_wf, null, raw);
                },
                (
                    response_buffer: Buffer,
                    cb_wf: Callback<
                        Partial<{
                            issuer: string;
                            name_id: string;
                            session_index: string;
                        }>
                    >
                ) => {
                    debug(saml_response as unknown as string);
                    const saml_response_abnormalized =
                        add_namespaces_to_child_assertions(
                            response_buffer.toString()
                        );
                    saml_response = new DOMParser().parseFromString(
                        saml_response_abnormalized
                    );
                    try {
                        response = {
                            response_header:
                                parse_response_header(saml_response),
                        };
                    } catch (error) {
                        return cb(error);
                    }
                    switch (false) {
                        case saml_response.getElementsByTagNameNS(
                            XMLNS.SAMLP,
                            'Response'
                        ).length !== 1:
                            if (!check_status_success(saml_response)) {
                                return cb_wf(
                                    new SAMLError(
                                        'SAML Response was not success!',
                                        {
                                            status: get_status(saml_response),
                                        }
                                    )
                                );
                            }
                            response.type = 'authn_response';
                            return parse_authn_response(
                                saml_response,
                                [this.private_key, ...(this.alt_private_keys || [])],
                                identity_provider.certificates,
                                options.allow_unencrypted_assertion,
                                options.ignore_signature,
                                options.require_session_index,
                                options.ignore_timing,
                                options.notbefore_skew,
                                options.audience,
                                cb_wf
                            );
                        case saml_response.getElementsByTagNameNS(
                            XMLNS.SAMLP,
                            'LogoutResponse'
                        ).length !== 1:
                            if (!check_status_success(saml_response)) {
                                return cb_wf(
                                    new SAMLError(
                                        'SAML Response was not success!',
                                        {
                                            status: get_status(saml_response),
                                        }
                                    )
                                );
                            }
                            response.type = 'logout_response';
                            return setImmediate(cb_wf, null, {});
                        case saml_response.getElementsByTagNameNS(
                            XMLNS.SAMLP,
                            'LogoutRequest'
                        ).length !== 1:
                            response.type = 'logout_request';
                            return setImmediate(
                                cb_wf,
                                null,
                                parse_logout_request(saml_response)
                            );
                    }
                },
                function (
                    result: Partial<{
                        issuer: string;
                        name_id: string;
                        session_index: string;
                    }>,
                    cb_wf: Callback<typeof response>
                ) {
                    extend(response, result);
                    return cb_wf(null, response);
                },
            ],
            cb
        );
    }
    // ----- Optional -----

    // Returns:
    //   Redirect URL, at which a user is logged out.
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_logout_request_url(
        identity_provider: Partial<IdentityProviderOptions>,
        options: any,
        cb: any
    ) {
        if (isString(identity_provider)) {
            identity_provider = {
                sso_logout_url: identity_provider,
                options: {},
            };
        }
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        const { id, xml } = create_logout_request(
            this.entity_id,
            options.name_id,
            options.session_index,
            identity_provider.sso_logout_url as string
        );
        return deflateRaw(xml, (err, deflated) => {
            let uri: UrlObject;
            if (err != null) {
                return cb(err);
            }
            try {
                uri = parse(identity_provider.sso_logout_url as string, true);
            } catch (error) {
                return cb(error);
            }
            let query = null;
            if (options.sign_get_request) {
                query = sign_request(
                    deflated.toString('base64'),
                    this.private_key,
                    options.relay_state
                );
            } else {
                query = {
                    SAMLRequest: deflated.toString('base64'),
                };
                if (options.relay_state !== null) {
                    (query as any).RelayState = options.relay_state;
                }
            }
            uri.query = extend(query, uri.query);
            uri.search = null;
            uri.query = query;
            return cb(null, format(uri), id);
        });
    }

    // Returns:
    //   Redirect URL to confirm a successful logout.
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_logout_response_url(
        identity_provider: Partial<IdentityProviderOptions>,
        options: any,
        cb: any
    ) {
        if (isString(identity_provider)) {
            identity_provider = {
                sso_logout_url: identity_provider,
                options: {},
            };
        }
        options = set_option_defaults(
            options,
            identity_provider.shared_options,
            this.shared_options
        );
        const xml = create_logout_response(
            this.entity_id,
            options.in_response_to,
            identity_provider.sso_logout_url as string
        );
        return deflateRaw(xml, (err, deflated) => {
            let uri: UrlObject;
            if (err != null) {
                return cb(err);
            }
            try {
                uri = parse(identity_provider.sso_logout_url as string);
            } catch (error) {
                return cb(error);
            }
            if (options.sign_get_request) {
                uri.query = sign_request(
                    deflated.toString('base64'),
                    this.private_key,
                    options.relay_state,
                    true
                );
            } else {
                uri.query = {
                    SAMLResponse: deflated.toString('base64'),
                };
                if (options.relay_state != null) {
                    uri.query.RelayState = options.relay_state;
                }
            }
            return cb(null, format(uri));
        });
    }
    // Returns:
    //   XML metadata, used during initial SAML configuration
    create_metadata() {
        const certs = [this.certificate, ...(this.alt_certs || [])];
        return create_metadata(
            this.entity_id,
            this.assert_endpoint,
            certs,
            certs
        );
    }
}

export class IdentityProvider {
    sso_login_url: string;
    sso_logout_url: string;
    certificates: string[];
    shared_options: { [key: string]: any };

    constructor(options: {
        sso_login_url: string;
        sso_logout_url: string;
        certificates: string | string[];
    }) {
        this.sso_login_url = options.sso_login_url;
        this.sso_logout_url = options.sso_logout_url;
        if (!isArray(options.certificates)) {
            this.certificates = [options.certificates];
        } else {
            this.certificates = options.certificates;
        }
        this.shared_options = pick(
            options,
            'force_authn',
            'sign_get_request',
            'allow_unencrypted_assertion'
        );
    }
}
