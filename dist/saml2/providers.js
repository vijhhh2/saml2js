"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityProvider = exports.ServiceProvider = void 0;
const lodash_1 = require("lodash");
const zlib_1 = require("zlib");
const url_1 = require("url");
const async_1 = require("async");
const debug_1 = __importDefault(require("debug"));
const xmldom_1 = require("@xmldom/xmldom");
const saml2_1 = require("./saml2");
const SAMLError_1 = require("./SAMLError");
class ServiceProvider {
    // Initializes a service provider given the passed options.
    // @entity_id, @private_key, @assert_endpoint, @certificate, @alt_private_keys, @alt_certs can
    // only be set here and are used by exported functions.
    // Rest of options can be set/overwritten by the identity provider and/or at function call.
    constructor(options) {
        this.alt_private_keys = [];
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
        this.alt_private_keys = [...(this.alt_private_keys || [])];
        this.alt_certs = [...(this.alt_certs || [])];
        this.shared_options = (0, lodash_1.pick)(options, 'force_authn', 'auth_context', 'nameid_format', 'sign_get_request', 'allow_unencrypted_assertion', 'audience', 'notbefore_skew');
    }
    // Returns:
    //   Redirect URL at which a user can login
    //   ID of the request
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_login_request_url(identity_provider, options, cb) {
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        const { id, xml } = (0, saml2_1.create_authn_request)(this.entity_id, this.assert_endpoint, identity_provider.sso_login_url, options.force_authn, options.auth_context, options.nameid_format);
        return (0, zlib_1.deflateRaw)(xml, (err, deflated) => {
            let uri;
            if (err !== null) {
                return cb(err);
            }
            try {
                uri = (0, url_1.parse)(identity_provider.sso_login_url, true);
            }
            catch (error) {
                return cb(error);
            }
            delete uri.search; // If you provide search and query search overrides query :/
            if (options.sign_get_request) {
                (0, lodash_1.extend)(uri.query, (0, saml2_1.sign_request)(deflated.toString('base64'), this.private_key, options.relay_state));
            }
            else {
                uri.query.SAMLRequest = deflated.toString('base64');
                if (options.relay_state != null) {
                    uri.query.RelayState = options.relay_state;
                }
            }
            return cb(null, (0, url_1.format)(uri), id);
        });
    }
    // Returns:
    //   An xml string with an AuthnRequest with an embedded xml signature
    // Params:
    //   identity_provider
    //   options
    create_authn_request_xml(identity_provider, options) {
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        const { id, xml } = (0, saml2_1.create_authn_request)(this.entity_id, this.assert_endpoint, identity_provider.sso_login_url, options.force_authn, options.auth_context, options.nameid_format);
        return (0, saml2_1.sign_authn_request)(xml, this.private_key, options);
    }
    // Returns:
    //   An object containing the parsed response for a redirect assert.
    //   This type of assert inflates the response before parsing it.
    // Params:
    //   identity_provider
    //   options
    //   cb
    redirect_assert(identity_provider, options, cb) {
        options = (0, lodash_1.defaults)((0, lodash_1.extend)(options, {
            get_request: true,
        }), {
            require_session_index: true,
        });
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        return this._assert(identity_provider, options, cb);
    }
    // Returns:
    //   An object containing the parsed response for a post assert.
    // Params:
    //   identity_provider
    //   options
    //   cb
    post_assert(identity_provider, options, cb) {
        options = (0, lodash_1.defaults)((0, lodash_1.extend)(options, {
            get_request: false,
        }), {
            require_session_index: true,
        });
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        return this._assert(identity_provider, options, cb);
    }
    // Private function, called by redirect and post assert to return a response to
    // corresponding assert.
    _assert(identity_provider, options, cb) {
        var _a, _b;
        if (!(((_a = options.request_body) === null || _a === void 0 ? void 0 : _a.SAMLResponse) ||
            ((_b = options.request_body) === null || _b === void 0 ? void 0 : _b.SAMLRequest))) {
            return setImmediate(cb, new Error('Request body does not contain SAMLResponse or SAMLRequest.'));
        }
        if (!(0, lodash_1.isNumber)(options.notbefore_skew)) {
            return setImmediate(cb, new Error('Configuration error: `notbefore_skew` must be a number'));
        }
        let saml_response = null;
        // todo: extract proper types instead of partial
        let response = {};
        return (0, async_1.waterfall)([
            function (cb_wf) {
                var raw;
                raw = Buffer.from(options.request_body.SAMLResponse ||
                    options.request_body.SAMLRequest, 'base64');
                // Inflate response for redirect requests before parsing it.
                if (options.get_request) {
                    return (0, zlib_1.inflateRaw)(raw, cb_wf);
                }
                return setImmediate(cb_wf, null, raw);
            },
            (response_buffer, cb_wf) => {
                (0, debug_1.default)(saml_response);
                const saml_response_abnormalized = (0, saml2_1.add_namespaces_to_child_assertions)(response_buffer.toString());
                saml_response = new xmldom_1.DOMParser().parseFromString(saml_response_abnormalized);
                try {
                    response = {
                        response_header: (0, saml2_1.parse_response_header)(saml_response),
                    };
                }
                catch (error) {
                    return cb(error);
                }
                switch (false) {
                    case saml_response.getElementsByTagNameNS(saml2_1.XMLNS.SAMLP, 'Response').length !== 1:
                        if (!(0, saml2_1.check_status_success)(saml_response)) {
                            return cb_wf(new SAMLError_1.SAMLError('SAML Response was not success!', {
                                status: (0, saml2_1.get_status)(saml_response),
                            }));
                        }
                        response.type = 'authn_response';
                        return (0, saml2_1.parse_authn_response)(saml_response, [this.private_key, ...(this.alt_private_keys || [])], identity_provider.certificates, options.allow_unencrypted_assertion, options.ignore_signature, options.require_session_index, options.ignore_timing, options.notbefore_skew, options.audience, cb_wf);
                    case saml_response.getElementsByTagNameNS(saml2_1.XMLNS.SAMLP, 'LogoutResponse').length !== 1:
                        if (!(0, saml2_1.check_status_success)(saml_response)) {
                            return cb_wf(new SAMLError_1.SAMLError('SAML Response was not success!', {
                                status: (0, saml2_1.get_status)(saml_response),
                            }));
                        }
                        response.type = 'logout_response';
                        return setImmediate(cb_wf, null, {});
                    case saml_response.getElementsByTagNameNS(saml2_1.XMLNS.SAMLP, 'LogoutRequest').length !== 1:
                        response.type = 'logout_request';
                        return setImmediate(cb_wf, null, (0, saml2_1.parse_logout_request)(saml_response));
                }
            },
            function (result, cb_wf) {
                (0, lodash_1.extend)(response, result);
                return cb_wf(null, response);
            },
        ], cb);
    }
    // ----- Optional -----
    // Returns:
    //   Redirect URL, at which a user is logged out.
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_logout_request_url(identity_provider, options, cb) {
        if ((0, lodash_1.isString)(identity_provider)) {
            identity_provider = {
                sso_logout_url: identity_provider,
                options: {},
            };
        }
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        const { id, xml } = (0, saml2_1.create_logout_request)(this.entity_id, options.name_id, options.session_index, identity_provider.sso_logout_url);
        return (0, zlib_1.deflateRaw)(xml, (err, deflated) => {
            let uri;
            if (err != null) {
                return cb(err);
            }
            try {
                uri = (0, url_1.parse)(identity_provider.sso_logout_url, true);
            }
            catch (error) {
                return cb(error);
            }
            let query = null;
            if (options.sign_get_request) {
                query = (0, saml2_1.sign_request)(deflated.toString('base64'), this.private_key, options.relay_state);
            }
            else {
                query = {
                    SAMLRequest: deflated.toString('base64'),
                };
                if (options.relay_state !== null) {
                    query.RelayState = options.relay_state;
                }
            }
            uri.query = (0, lodash_1.extend)(query, uri.query);
            uri.search = null;
            uri.query = query;
            return cb(null, (0, url_1.format)(uri), id);
        });
    }
    // Returns:
    //   Redirect URL to confirm a successful logout.
    // Params:
    //   identity_provider
    //   options
    //   cb
    create_logout_response_url(identity_provider, options, cb) {
        if ((0, lodash_1.isString)(identity_provider)) {
            identity_provider = {
                sso_logout_url: identity_provider,
                options: {},
            };
        }
        options = (0, saml2_1.set_option_defaults)(options, identity_provider.shared_options, this.shared_options);
        const xml = (0, saml2_1.create_logout_response)(this.entity_id, options.in_response_to, identity_provider.sso_logout_url);
        return (0, zlib_1.deflateRaw)(xml, (err, deflated) => {
            let uri;
            if (err != null) {
                return cb(err);
            }
            try {
                uri = (0, url_1.parse)(identity_provider.sso_logout_url);
            }
            catch (error) {
                return cb(error);
            }
            if (options.sign_get_request) {
                uri.query = (0, saml2_1.sign_request)(deflated.toString('base64'), this.private_key, options.relay_state, true);
            }
            else {
                uri.query = {
                    SAMLResponse: deflated.toString('base64'),
                };
                if (options.relay_state != null) {
                    uri.query.RelayState = options.relay_state;
                }
            }
            return cb(null, (0, url_1.format)(uri));
        });
    }
    // Returns:
    //   XML metadata, used during initial SAML configuration
    create_metadata() {
        const certs = [this.certificate, ...(this.alt_certs || [])];
        return (0, saml2_1.create_metadata)(this.entity_id, this.assert_endpoint, certs, certs);
    }
}
exports.ServiceProvider = ServiceProvider;
class IdentityProvider {
    constructor(options) {
        this.sso_login_url = options.sso_login_url;
        this.sso_logout_url = options.sso_logout_url;
        if (!(0, lodash_1.isArray)(options.certificates)) {
            this.certificates = [options.certificates];
        }
        else {
            this.certificates = options.certificates;
        }
        this.shared_options = (0, lodash_1.pick)(options, 'force_authn', 'sign_get_request', 'allow_unencrypted_assertion');
    }
}
exports.IdentityProvider = IdentityProvider;
