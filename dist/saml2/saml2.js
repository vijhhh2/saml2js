"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.set_option_defaults = exports.parse_logout_request = exports.parse_authn_response = exports.add_namespaces_to_child_assertions = exports.pretty_assertion_attributes = exports.parse_assertion_attributes = exports.get_session_info = exports.get_name_id = exports.parse_response_header = exports.check_saml_signature = exports.get_signed_data = exports.decrypt_assertion = exports.to_error = exports.get_status = exports.check_status_success = exports.get_attribute_value = exports.sign_request = exports.format_pem = exports.create_logout_response = exports.create_logout_request = exports.create_metadata = exports.certificate_to_keyinfo = exports.extract_certificate_data = exports.sign_authn_request = exports.create_authn_request = exports.XMLNS = void 0;
const xmlbuilder2_1 = require("xmlbuilder2");
const crypto_1 = require("crypto");
const xml_crypto_1 = require("xml-crypto");
const xmldom_1 = require("@xmldom/xmldom");
const util_1 = require("util");
const async_1 = require("async");
const xml_encryption_1 = require("xml-encryption");
const debug_1 = __importDefault(require("debug"));
const debug = (0, debug_1.default)('saml2');
const SAMLError_1 = require("./SAMLError");
const lodash_1 = require("lodash");
exports.XMLNS = {
    SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
    SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
    MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
    DS: 'http://www.w3.org/2000/09/xmldsig#',
    XENC: 'http://www.w3.org/2001/04/xmlenc#',
    EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#',
};
// Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created request
const create_authn_request = (issuer, assert_endpoint, destination, force_authn, context, nameid_format) => {
    let context_element;
    let id = '_' + (0, crypto_1.randomBytes)(21).toString('hex');
    if (context) {
        context_element = {
            'saml:AuthnContextClassRef': context.class_refs,
            '@Comparison': context.comparison,
        };
    }
    const xml = (0, xmlbuilder2_1.create)({
        AuthnRequest: {
            '@xmlns': exports.XMLNS.SAMLP,
            '@xmlns:saml': exports.XMLNS.SAML,
            '@Version': '2.0',
            '@ID': id,
            '@IssueInstant': new Date().toISOString(),
            '@Destination': destination,
            '@AssertionConsumerServiceURL': assert_endpoint,
            '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            '@ForceAuthn': force_authn,
            'saml:Issuer': issuer,
        },
        // NameIDPolicy: {
        //     '@Format':
        //         nameid_format ||
        //         'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        //     '@AllowCreate': 'true',
        // },
        // RequestedAuthnContext: context_element,
    }).end();
    return { xml, id };
};
exports.create_authn_request = create_authn_request;
// Adds an embedded signature to a previously generated AuthnRequest
const sign_authn_request = (xml, private_key, options) => {
    const signer = new xml_crypto_1.SignedXml(null, options);
    signer.addReference("//*[local-name(.)='AuthnRequest']", [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
    ]);
    signer.signingKey = private_key;
    signer.computeSignature(xml);
    return signer.getSignedXml();
};
exports.sign_authn_request = sign_authn_request;
// Returns the raw certificate data with all extraneous characters removed.
const extract_certificate_data = function (certificate) {
    let cert_data;
    cert_data =
        /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(certificate);
    cert_data = cert_data != null ? cert_data[1] : certificate;
    if (cert_data == null) {
        throw new Error('Invalid Certificate');
    }
    return cert_data.replace(/[\r\n]/g, '');
};
exports.extract_certificate_data = extract_certificate_data;
// Converts a pem certificate to a KeyInfo object for use with XML.
const certificate_to_keyinfo = (use, certificate) => {
    return {
        '@use': use,
        'ds:KeyInfo': {
            '@xmlns:ds': exports.XMLNS.DS,
            'ds:X509Data': {
                'ds:X509Certificate': (0, exports.extract_certificate_data)(certificate),
            },
        },
    };
};
exports.certificate_to_keyinfo = certificate_to_keyinfo;
// Creates metadata and returns it as a string of XML. The metadata has one POST assertion endpoint.
const create_metadata = (entity_id, assert_endpoint, signing_certificates, encryption_certificates) => {
    const signing_cert_descriptors = signing_certificates.map((signing_certificate) => {
        return (0, exports.certificate_to_keyinfo)('signing', signing_certificate);
    }) || [];
    const encryption_cert_descriptors = encryption_certificates.map((encryption_certificate) => {
        return (0, exports.certificate_to_keyinfo)('encryption', encryption_certificate);
    }) || [];
    return (0, xmlbuilder2_1.create)({
        'md:EntityDescriptor': {
            '@xmlns:md': exports.XMLNS.MD,
            '@xmlns:ds': exports.XMLNS.DS,
            '@entityID': entity_id,
            '@validUntil': new Date(Date.now() + 1000 * 60 * 60).toISOString(),
            'md:SPSSODescriptor': {
                '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
                'md:KeyDescriptor': signing_cert_descriptors.concat(encryption_cert_descriptors),
                'md:SingleLogoutService': {
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    '@Location': assert_endpoint,
                },
                'md:AssertionConsumerService': {
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    '@Location': assert_endpoint,
                    '@index': '0',
                },
            },
        },
    }).end();
};
exports.create_metadata = create_metadata;
// Creates a LogoutRequest and returns it as a string of xml.
const create_logout_request = function (issuer, name_id, session_index, destination) {
    const id = '_' + (0, crypto_1.randomBytes)(21).toString('hex');
    const xml = (0, xmlbuilder2_1.create)({
        'samlp:LogoutRequest': {
            '@xmlns:samlp': exports.XMLNS.SAMLP,
            '@xmlns:saml': exports.XMLNS.SAML,
            '@ID': id,
            '@Version': '2.0',
            '@IssueInstant': new Date().toISOString(),
            '@Destination': destination,
            'saml:Issuer': issuer,
            'saml:NameID': name_id,
            'samlp:SessionIndex': session_index,
        },
    }).end();
    return { id, xml };
};
exports.create_logout_request = create_logout_request;
// Creates a LogoutResponse and returns it as a string of xml.
const create_logout_response = (issuer, in_response_to, destination, status = 'urn:oasis:names:tc:SAML:2.0:status:Success') => {
    return (0, xmlbuilder2_1.create)({
        'samlp:LogoutResponse': {
            '@Destination': destination,
            '@ID': '_' + (0, crypto_1.randomBytes)(21).toString('hex'),
            '@InResponseTo': in_response_to,
            '@IssueInstant': new Date().toISOString(),
            '@Version': '2.0',
            '@xmlns:samlp': exports.XMLNS.SAMLP,
            '@xmlns:saml': exports.XMLNS.SAML,
            'saml:Issuer': issuer,
            'samlp:Status': {
                'samlp:StatusCode': { '@Value': status },
            },
        },
    }).end({ headless: true });
};
exports.create_logout_response = create_logout_response;
// Takes a base64 encoded @key and returns it formatted with newlines and a PEM header according to @type.
// If it already has a PEM header, it will just return the original key.
const format_pem = (key, type) => {
    var _a;
    if (/-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g.exec(key) !=
        null) {
        return key;
    }
    return (`-----BEGIN ${type.toUpperCase()}-----\n` +
        ((_a = key.match(/.{1,64}/g)) === null || _a === void 0 ? void 0 : _a.join('\n')) +
        `\n-----END ${type.toUpperCase()}-----`);
};
exports.format_pem = format_pem;
// Takes a compressed/base64 enoded @saml_request and @private_key and signs the request using RSA-SHA256. It returns
// the result as an object containing the query parameters.
const sign_request = (saml_request, private_key, relay_state, response = false) => {
    //   var action, data, relay_state_data, samlQueryString, saml_request_data, sigalg_data, sign;
    const action = response ? 'SAMLResponse' : 'SAMLRequest';
    let data = `${action}=` + encodeURIComponent(saml_request);
    if (relay_state) {
        data += '&RelayState=' + encodeURIComponent(relay_state);
    }
    data +=
        '&SigAlg=' +
            encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    const saml_request_data = `${action}=` + encodeURIComponent(saml_request);
    const relay_state_data = relay_state != null
        ? '&RelayState=' + encodeURIComponent(relay_state)
        : '';
    const sigalg_data = '&SigAlg=' +
        encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    const sign = (0, crypto_1.createSign)('RSA-SHA256');
    sign.update(saml_request_data + relay_state_data + sigalg_data);
    const samlQueryString = {};
    if (response) {
        (0, lodash_1.set)(samlQueryString, 'SAMLResponse', saml_request);
    }
    else {
        (0, lodash_1.set)(samlQueryString, 'SAMLRequest', saml_request);
    }
    if (relay_state) {
        (0, lodash_1.set)(samlQueryString, 'RelayState', relay_state);
    }
    (0, lodash_1.set)(samlQueryString, 'SigAlg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    (0, lodash_1.set)(samlQueryString, 'Signature', sign.sign((0, exports.format_pem)(private_key, 'PRIVATE KEY'), 'base64'));
    return samlQueryString;
};
exports.sign_request = sign_request;
// Takes a node XMLDom node and gets the attribute value
const get_attribute_value = function (node, attributeName) {
    var _a;
    const attributes = node.attributes || [];
    const attribute = (0, lodash_1.filter)(attributes, (attr) => {
        return attr.name === attributeName;
    });
    return (_a = attribute[0]) === null || _a === void 0 ? void 0 : _a.value;
};
exports.get_attribute_value = get_attribute_value;
// Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
const check_status_success = (dom) => {
    const status = dom.getElementsByTagNameNS(exports.XMLNS.SAMLP, 'Status');
    if (status.length !== 1) {
        return false;
    }
    const ref = status[0].childNodes || [];
    return (0, lodash_1.some)(ref, (status_code) => {
        if (status_code.attributes !== null) {
            const status = (0, exports.get_attribute_value)(status_code, 'Value');
            return status === 'urn:oasis:names:tc:SAML:2.0:status:Success';
        }
    });
};
exports.check_status_success = check_status_success;
const get_status = (dom) => {
    const status_list = {};
    const status = dom.getElementsByTagNameNS(exports.XMLNS.SAMLP, 'Status');
    if (status.length !== 1) {
        return status_list;
    }
    let top_status;
    (status[0].childNodes || []).forEach((status_code) => {
        if (status_code.attributes !== null) {
            top_status = (0, exports.get_attribute_value)(status_code, 'Value');
            if (status_list[top_status] == null) {
                status_list[top_status] = [];
            }
        }
        (status_code.childNodes || []).forEach((sub_status_code) => {
            if ((sub_status_code === null || sub_status_code === void 0 ? void 0 : sub_status_code.attributes) !== null) {
                const status = (0, exports.get_attribute_value)(sub_status_code, 'Value');
                status_list[top_status].push(status);
            }
        });
    });
    return status_list;
};
exports.get_status = get_status;
const to_error = (err) => {
    if (err === null) {
        return null;
    }
    if (!(err instanceof Error)) {
        return new Error((0, util_1.inspect)(err));
    }
    return err;
};
exports.to_error = to_error;
// Takes in an XML @dom of an object containing an EncryptedAssertion and attempts to decrypt it
// using the @private_keys in the given order.
// @cb will be called with an error if the decryption fails, or the EncryptedAssertion cannot be
// found. If successful, it will be called with the decrypted data as a string.
// Todo: Remove async dependency by converting it to promises
const decrypt_assertion = (dom, private_keys, cb) => {
    // This is needed because xmlenc sometimes throws an exception, and sometimes calls the passed-in
    // callback.
    cb = (0, lodash_1.wrap)(cb, function (fn, err, result) {
        return setTimeout(() => {
            return fn((0, exports.to_error)(err), result);
        }, 0);
    });
    try {
        let encrypted_assertion = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'EncryptedAssertion');
        if (encrypted_assertion.length !== 1) {
            return cb(new Error(`Expected 1 EncryptedAssertion; found ${encrypted_assertion.length}.`));
        }
        const encrypted_data = encrypted_assertion[0].getElementsByTagNameNS(exports.XMLNS.XENC, 'EncryptedData');
        if (encrypted_data.length !== 1) {
            return cb(new Error(`Expected 1 EncryptedData inside EncryptedAssertion; found ${encrypted_data.length}.`));
        }
        const encrypted_assertion_string = encrypted_assertion[0].toString();
        const errors = [];
        return (0, async_1.eachOfSeries)(private_keys, function (private_key, index, cb_e) {
            return (0, xml_encryption_1.decrypt)(encrypted_assertion_string, {
                key: (0, exports.format_pem)(private_key, 'PRIVATE KEY'),
            }, function (err, result) {
                if (err !== null) {
                    if (err !== null) {
                        errors.push(new Error(`Decrypt failed: ${(0, util_1.inspect)(err)}`));
                    }
                    return cb_e();
                }
                debug(`Decryption successful with private key #${index}.`);
                return cb(null, result);
            });
        }, function () {
            return cb(new Error(`Failed to decrypt assertion with provided key(s): ${(0, util_1.inspect)(errors)}`));
        });
    }
    catch (error) {
        return cb(new Error(`Decrypt failed: ${(0, util_1.inspect)(error)}`));
    }
};
exports.decrypt_assertion = decrypt_assertion;
// Gets the data that is actually signed according to xml-crypto. This function should mirror the way xml-crypto finds
// elements for security reasons.
const get_signed_data = (doc, sig) => {
    return (0, lodash_1.map)(sig.references, (ref) => {
        var i, idAttribute, len, ref1;
        let uri = ref.uri;
        if (uri && uri[0] === '#') {
            uri = uri.substring(1);
        }
        let elem = [];
        if (uri === '') {
            elem = (0, xml_crypto_1.xpath)(doc, '//*');
        }
        else {
            ref1 = ['Id', 'ID'];
            for (i = 0, len = ref1.length; i < len; i++) {
                idAttribute = ref1[i];
                elem = (0, xml_crypto_1.xpath)(doc, "//*[@*[local-name(.)='" + idAttribute + "']='" + uri + "']");
                if (elem.length > 0) {
                    break;
                }
            }
        }
        if (!(elem.length > 0)) {
            throw new Error(`Invalid signature; must be a reference to '${ref.uri}'`);
        }
        return sig.getCanonXml(ref.transforms, elem[0], {
            inclusiveNamespacesPrefixList: ref.inclusiveNamespacesPrefixList,
        });
    });
};
exports.get_signed_data = get_signed_data;
// This checks the signature of a saml document and returns either array containing the signed data if valid, or null
// if the signature is invalid. Comparing the result against null is NOT sufficient for signature checks as it doesn't
// verify the signature is signing the important content, nor is it preventing the parsing of unsigned content.
const check_saml_signature = (_xml, certificate) => {
    // xml-crypto requires that whitespace is normalized as such:
    // https://github.com/yaronn/xml-crypto/commit/17f75c538674c0afe29e766b058004ad23bd5136#diff-5dfe38baf287dcf756a17c2dd63483781b53bf4b669e10efdd01e74bcd8e780aL69
    const xml = _xml.replace(/\r\n?/g, '\n');
    const doc = new xmldom_1.DOMParser().parseFromString(xml);
    // xpath failed to capture <ds:Signature> nodes of direct descendents of the root.
    // Call documentElement to explicitly start from the root element of the document.
    const signature = (0, xml_crypto_1.xpath)(doc.documentElement, "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']");
    if (signature.length !== 1) {
        return null;
    }
    const sig = new xml_crypto_1.SignedXml();
    sig.keyInfoProvider = {
        getKey: function () {
            return (0, exports.format_pem)(certificate, 'CERTIFICATE');
        },
    };
    sig.loadSignature(signature[0]);
    const valid = sig.checkSignature(xml);
    if (valid) {
        return (0, exports.get_signed_data)(doc, sig);
    }
    else {
        return null;
    }
};
exports.check_saml_signature = check_saml_signature;
// Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
// InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
// appear to be valid.
const parse_response_header = (dom) => {
    let response = [];
    for (let response_type of ['Response', 'LogoutResponse', 'LogoutRequest']) {
        response = dom.getElementsByTagNameNS(exports.XMLNS.SAMLP, response_type);
        if (response.length > 0) {
            break;
        }
    }
    if (response.length !== 1) {
        throw new Error(`Expected 1 Response; found ${response.length}`);
    }
    const response_header = {
        version: (0, exports.get_attribute_value)(response[0], 'Version'),
        destination: (0, exports.get_attribute_value)(response[0], 'Destination'),
        in_response_to: (0, exports.get_attribute_value)(response[0], 'InResponseTo'),
        id: (0, exports.get_attribute_value)(response[0], 'ID'),
    };
    // If no version attribute is supplied, assume v2
    const version = response_header.version || '2.0';
    if (version !== '2.0') {
        throw new Error(`Invalid SAML Version ${version}`);
    }
    return response_header;
};
exports.parse_response_header = parse_response_header;
// Takes in an xml @dom of an object containing a SAML Assertion and returns the NameID. If there is no NameID found,
// it will return null. It will throw an error if the Assertion is missing or does not appear to be valid.
const get_name_id = (dom) => {
    var _a;
    var ref;
    const assertion = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const subject = assertion[0].getElementsByTagNameNS(exports.XMLNS.SAML, 'Subject');
    if (subject.length !== 1) {
        throw new Error(`Expected 1 Subject; found ${subject.length}`);
    }
    const nameid = subject[0].getElementsByTagNameNS(exports.XMLNS.SAML, 'NameID');
    if (nameid.length !== 1) {
        return null;
    }
    return (_a = nameid[0].firstChild) === null || _a === void 0 ? void 0 : _a.data;
};
exports.get_name_id = get_name_id;
// Takes in an xml @dom of an object containing a SAML Assertion and returns the SessionIndex. It will throw an error
// if there is no SessionIndex, no Assertion, or the Assertion does not appear to be valid. Optionally you can pass a
// second argument `false` making SessionIndex optional. Doing so returns `null` instead of throwing an Error if the
// SessionIndex attribute does not exist.
const get_session_info = (dom, index_required = true) => {
    const assertion = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const authn_statement = assertion[0].getElementsByTagNameNS(exports.XMLNS.SAML, 'AuthnStatement');
    if (authn_statement.length !== 1) {
        throw new Error(`Expected 1 AuthnStatement; found ${authn_statement.length}`);
    }
    const info = {
        index: (0, exports.get_attribute_value)(authn_statement[0], 'SessionIndex'),
        not_on_or_after: (0, exports.get_attribute_value)(authn_statement[0], 'SessionNotOnOrAfter'),
    };
    if (index_required && info.index === null) {
        throw new Error('SessionIndex not an attribute of AuthnStatement.');
    }
    return info;
};
exports.get_session_info = get_session_info;
// Takes in an xml @dom of an object containing a SAML Assertion and returns and object containing the attributes
// contained within the Assertion. It will throw an error if the Assertion is missing or does not appear to be valid.
const parse_assertion_attributes = (dom) => {
    const assertion = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const attribute_statement = assertion[0].getElementsByTagNameNS(exports.XMLNS.SAML, 'AttributeStatement');
    if (!(attribute_statement.length <= 1)) {
        throw new Error(`Expected 1 AttributeStatement inside Assertion; found ${attribute_statement.length}`);
    }
    if (attribute_statement.length === 0) {
        return {};
    }
    const attributes = attribute_statement[0].getElementsByTagNameNS(exports.XMLNS.SAML, 'Attribute');
    return (0, lodash_1.reduce)(attributes, (acc, attribute) => {
        const attribute_name = (0, exports.get_attribute_value)(attribute, 'Name');
        if (attribute_name == null) {
            throw new Error('Invalid attribute without name');
        }
        const attribute_values = attribute.getElementsByTagNameNS(exports.XMLNS.SAML, 'AttributeValue');
        acc[attribute_name] =
            (0, lodash_1.map)(attribute_values, (attribute_value) => { var _a; return (_a = attribute_value.childNodes[0]) === null || _a === void 0 ? void 0 : _a.data; }) || '';
        return acc;
    }, {});
};
exports.parse_assertion_attributes = parse_assertion_attributes;
// Takes in an object containing SAML Assertion Attributes and returns an object with certain common attributes changed
// into nicer names. Attributes that are not expected are ignored, and attributes with more than one value with have
// all values except the first one dropped.
const pretty_assertion_attributes = (assertion_attributes) => {
    const claim_map = {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'given_name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': 'upn',
        'http://schemas.xmlsoap.org/claims/CommonName': 'common_name',
        'http://schemas.xmlsoap.org/claims/Group': 'group',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': 'role',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'surname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier': 'ppid',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'name_id',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod': 'authentication_method',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid': 'deny_only_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid': 'deny_only_primary_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid': 'deny_only_primary_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid': 'group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid': 'primary_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid': 'primary_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname': 'windows_account_name',
    };
    return (0, lodash_1.chain)(assertion_attributes)
        .toPairs()
        .filter(([k, v]) => claim_map[k] !== null && v.length > 0)
        .map(([k, v]) => [claim_map[k], v[0]])
        .fromPairs()
        .value();
};
exports.pretty_assertion_attributes = pretty_assertion_attributes;
// takes in an XML string, returns an XML string
// applies all inclusive namespaces for signature assertions onto assertion tag
// used as recommended workaround for xml-crypto library limitation with inclusive namespaces
// see https://github.com/yaronn/xml-crypto/issues/48#issuecomment-129705816
const add_namespaces_to_child_assertions = (xml_string) => {
    var _a;
    const doc = new xmldom_1.DOMParser().parseFromString(xml_string);
    const response_elements = doc.getElementsByTagNameNS(exports.XMLNS.SAMLP, 'Response');
    if (response_elements.length !== 1) {
        return xml_string;
    }
    const response_element = response_elements[0];
    const assertion_elements = response_element.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
    if (assertion_elements.length !== 1) {
        return xml_string;
    }
    const assertion_element = assertion_elements[0];
    const inclusive_namespaces = assertion_element.getElementsByTagNameNS(exports.XMLNS.EXC_C14N, 'InclusiveNamespaces')[0];
    const prefixList = (_a = inclusive_namespaces.getAttribute('PrefixList')) === null || _a === void 0 ? void 0 : _a.trim();
    const namespaces = inclusive_namespaces && prefixList
        ? prefixList.split(' ').map((ns) => `xmlns:${ns}`)
        : (0, lodash_1.reduce)(response_element.attributes, (acc, attr) => {
            if (attr.name.match(/^xmlns:/)) {
                return [...acc, attr.name];
            }
            return acc;
        }, []);
    // add the namespaces that are present in response and missing in assertion.
    namespaces.forEach((ns) => {
        if (response_element.getAttribute(ns) &&
            !assertion_element.getAttribute(ns)) {
            const new_attribute = doc.createAttribute(ns);
            new_attribute.value = response_element.getAttribute(ns);
            assertion_element.setAttributeNode(new_attribute);
        }
    });
    return new XMLSerializer().serializeToString(response_element);
};
exports.add_namespaces_to_child_assertions = add_namespaces_to_child_assertions;
// Takes a DOM of a saml_response, private keys with which to attempt decryption and the
// certificate(s) of the identity provider that issued it and will return a user object containing
// the attributes or an error if keys are incorrect or the response is invalid.
// Todo: Remove async dependency by converting it to promises
const parse_authn_response = (saml_response, sp_private_keys, idp_certificates, allow_unencrypted, ignore_signature, require_session_index, ignore_timing, notbefore_skew, sp_audience, cb) => {
    let user = {};
    return (0, async_1.waterfall)([
        function (cb_wf) {
            // Decrypt the assertion
            return (0, exports.decrypt_assertion)(saml_response, sp_private_keys, function (err, result) {
                if (err === null) {
                    return cb_wf(null, result);
                }
                if (!(allow_unencrypted &&
                    (err === null || err === void 0 ? void 0 : err.message) ===
                        'Expected 1 EncryptedAssertion; found 0.')) {
                    return cb_wf(err, result);
                }
                const assertion = saml_response.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
                if (assertion.length !== 1) {
                    return cb_wf(new Error(`Expected 1 Assertion or 1 EncryptedAssertion; found ${assertion.length}`));
                }
                return cb_wf(null, assertion[0].toString());
            });
        },
        function (result, cb_wf) {
            // Validate the signature
            debug(result);
            if (ignore_signature) {
                return cb_wf(null, new xmldom_1.DOMParser().parseFromString(result));
            }
            const saml_response_str = saml_response.toString();
            idp_certificates.forEach((cert, index) => {
                let signed_data;
                try {
                    signed_data =
                        (0, exports.check_saml_signature)(result, cert) ||
                            (0, exports.check_saml_signature)(saml_response_str, cert);
                }
                catch (error) {
                    return cb_wf(new Error(`SAML Assertion signature check failed! (Certificate \#${index + 1} may be invalid. ${error.message}`));
                }
                if (signed_data) {
                    signed_data === null || signed_data === void 0 ? void 0 : signed_data.forEach((sd) => {
                        const signed_dom = new xmldom_1.DOMParser().parseFromString(sd);
                        const assertion = signed_dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'Assertion');
                        if (assertion.length === 1) {
                            return cb_wf(null, signed_dom);
                        }
                        const encryptedAssertion = signed_dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'EncryptedAssertion');
                        if (encryptedAssertion.length === 1) {
                            return (0, exports.decrypt_assertion)(saml_response, sp_private_keys, function (err, result) {
                                if (err === null && result) {
                                    return cb_wf(null, new xmldom_1.DOMParser().parseFromString(result));
                                }
                                return cb_wf(err);
                            });
                        }
                    });
                    return cb_wf(new Error('Signed data did not contain a SAML Assertion!'));
                }
                // else Cert was not valid, try the next one
            });
            return cb_wf(new Error(`SAML Assertion signature check failed! (checked ${idp_certificates.length} certificate(s))`));
        },
        function (decrypted_assertion, cb_wf) {
            // Validate the assertion conditions
            const conditions = decrypted_assertion.getElementsByTagNameNS(exports.XMLNS.SAML, 'Conditions')[0];
            if (conditions !== null) {
                if (ignore_timing !== true) {
                    for (let attribute of conditions.attributes) {
                        const condition = attribute.name.toLowerCase();
                        if (condition === 'notbefore' &&
                            Date.parse(attribute.value) >
                                Date.now() + notbefore_skew * 1000) {
                            return cb_wf(new SAMLError_1.SAMLError('SAML Response is not yet valid', {
                                NotBefore: attribute.value,
                            }));
                        }
                        if (condition === 'notonorafter' &&
                            Date.parse(attribute.value) <= Date.now()) {
                            return cb_wf(new SAMLError_1.SAMLError('SAML Response is no longer valid', {
                                NotOnOrAfter: attribute.value,
                            }));
                        }
                    }
                }
                const audience_restriction = conditions.getElementsByTagNameNS(exports.XMLNS.SAML, 'AudienceRestriction')[0];
                const audiences = (audience_restriction === null || audience_restriction === void 0 ? void 0 : audience_restriction.getElementsByTagNameNS(exports.XMLNS.SAML, 'Audience')) || [];
                if (audiences.length > 0) {
                    const validAudience = (0, lodash_1.find)(audiences, (audience) => {
                        var _a, _b;
                        const audienceValue = (_b = (_a = audience.firstChild) === null || _a === void 0 ? void 0 : _a.data) === null || _b === void 0 ? void 0 : _b.trim();
                        return (!(0, lodash_1.isEmpty)(audienceValue === null || audienceValue === void 0 ? void 0 : audienceValue.trim()) &&
                            (((0, lodash_1.isRegExp)(sp_audience) &&
                                sp_audience.test(audienceValue)) ||
                                ((0, lodash_1.isString)(sp_audience) &&
                                    sp_audience.toLowerCase() ===
                                        audienceValue.toLowerCase())));
                    });
                    if (validAudience == null) {
                        return cb_wf(new SAMLError_1.SAMLError('SAML Response is not valid for this audience'));
                    }
                }
            }
            return cb_wf(null, decrypted_assertion);
        },
        function (validated_assertion, cb_wf) {
            var err, session_info;
            try {
                // Populate attributes
                session_info = (0, exports.get_session_info)(validated_assertion, require_session_index);
                user.name_id = (0, exports.get_name_id)(validated_assertion);
                user.session_index = session_info.index;
                if (session_info.not_on_or_after !== null) {
                    user.session_not_on_or_after =
                        session_info.not_on_or_after;
                }
                const assertion_attributes = (0, exports.parse_assertion_attributes)(validated_assertion);
                user = (0, lodash_1.extend)(user, (0, exports.pretty_assertion_attributes)(assertion_attributes));
                user = (0, lodash_1.extend)(user, {
                    attributes: assertion_attributes,
                });
                return cb_wf(null, { user });
            }
            catch (error) {
                return cb_wf(error);
            }
        },
    ], cb);
};
exports.parse_authn_response = parse_authn_response;
const parse_logout_request = function (dom) {
    var _a, _b, _c;
    const request = dom.getElementsByTagNameNS(exports.XMLNS.SAMLP, 'LogoutRequest');
    if (request.length !== 1) {
        throw new Error(`Expected 1 LogoutRequest; found ${request.length}`);
    }
    const logOutRequest = {};
    const issuer = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'Issuer');
    if (issuer.length === 1) {
        logOutRequest.issuer = (_a = issuer[0].firstChild) === null || _a === void 0 ? void 0 : _a.data;
    }
    const name_id = dom.getElementsByTagNameNS(exports.XMLNS.SAML, 'NameID');
    if (name_id.length === 1) {
        logOutRequest.name_id = (_b = name_id[0].firstChild) === null || _b === void 0 ? void 0 : _b.data;
    }
    const session_index = dom.getElementsByTagNameNS(exports.XMLNS.SAMLP, 'SessionIndex');
    if (session_index.length === 1) {
        logOutRequest.session_index = (_c = session_index[0].firstChild) === null || _c === void 0 ? void 0 : _c.data;
    }
    return logOutRequest;
};
exports.parse_logout_request = parse_logout_request;
const set_option_defaults = (request_options, idp_options, sp_options) => {
    return (0, lodash_1.defaults)({}, request_options, idp_options, sp_options);
};
exports.set_option_defaults = set_option_defaults;
