import { create } from 'xmlbuilder2';
import { createSign, randomBytes } from 'crypto';
import { SignedXml, xpath } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { inspect } from 'util';
import { eachOfSeries, waterfall } from 'async';
import { decrypt } from 'xml-encryption';
import debugModule from 'debug';

const debug = debugModule('saml2');

import { SAMLError } from './SAMLError';
import {
    chain,
    filter,
    map,
    set,
    wrap,
    toPairs,
    reduce,
    find,
    isEmpty,
    isRegExp,
    isString,
    extend,
    defaults,
    some,
} from 'lodash';

export type Callback<T> = (error?: Error | null, result?: T) => void;
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
export const XMLNS = {
    SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
    SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
    MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
    DS: 'http://www.w3.org/2000/09/xmldsig#',
    XENC: 'http://www.w3.org/2001/04/xmlenc#',
    EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#',
};
// Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created request
export const create_authn_request = (
    issuer: string,
    assert_endpoint: string,
    destination: string,
    force_authn: boolean,
    context?: any,
    nameid_format?: string
) => {
    let context_element;
    let id = '_' + randomBytes(21).toString('hex');
    if (context) {
        context_element = {
            'saml:AuthnContextClassRef': context.class_refs,
            '@Comparison': context.comparison,
        };
    }
    const xml = create({
        AuthnRequest: {
            '@xmlns': XMLNS.SAMLP,
            '@xmlns:saml': XMLNS.SAML,
            '@Version': '2.0',
            '@ID': id,
            '@IssueInstant': new Date().toISOString(),
            '@Destination': destination,
            '@AssertionConsumerServiceURL': assert_endpoint,
            '@ProtocolBinding':
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
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

// Adds an embedded signature to a previously generated AuthnRequest
export const sign_authn_request = (
    xml: string,
    private_key: string,
    options: any
) => {
    const signer = new SignedXml(null, options);
    signer.addReference("//*[local-name(.)='AuthnRequest']", [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
    ]);
    signer.signingKey = private_key;
    signer.computeSignature(xml);
    return signer.getSignedXml();
};

// Returns the raw certificate data with all extraneous characters removed.
export const extract_certificate_data = function (certificate: string): string {
    let cert_data;
    cert_data =
        /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
            certificate
        );
    cert_data = cert_data != null ? cert_data[1] : certificate;
    if (cert_data == null) {
        throw new Error('Invalid Certificate');
    }
    return cert_data.replace(/[\r\n]/g, '');
};

// Converts a pem certificate to a KeyInfo object for use with XML.
export const certificate_to_keyinfo = (use: string, certificate: string) => {
    return {
        '@use': use,
        'ds:KeyInfo': {
            '@xmlns:ds': XMLNS.DS,
            'ds:X509Data': {
                'ds:X509Certificate': extract_certificate_data(certificate),
            },
        },
    };
};

// Creates metadata and returns it as a string of XML. The metadata has one POST assertion endpoint.
export const create_metadata = (
    entity_id: string,
    assert_endpoint: string,
    signing_certificates: string[],
    encryption_certificates: string[]
) => {
    const signing_cert_descriptors =
        signing_certificates.map((signing_certificate) => {
            return certificate_to_keyinfo('signing', signing_certificate);
        }) || [];
    const encryption_cert_descriptors =
        encryption_certificates.map((encryption_certificate) => {
            return certificate_to_keyinfo('encryption', encryption_certificate);
        }) || [];
    return create({
        'md:EntityDescriptor': {
            '@xmlns:md': XMLNS.MD,
            '@xmlns:ds': XMLNS.DS,
            '@entityID': entity_id,
            '@validUntil': new Date(Date.now() + 1000 * 60 * 60).toISOString(),
            'md:SPSSODescriptor': {
                '@protocolSupportEnumeration':
                    'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
                'md:KeyDescriptor': signing_cert_descriptors.concat(
                    encryption_cert_descriptors
                ),
                'md:SingleLogoutService': {
                    '@Binding':
                        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    '@Location': assert_endpoint,
                },
                'md:AssertionConsumerService': {
                    '@Binding':
                        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    '@Location': assert_endpoint,
                    '@index': '0',
                },
            },
        },
    }).end();
};

// Creates a LogoutRequest and returns it as a string of xml.
export const create_logout_request = function (
    issuer: string,
    name_id: string,
    session_index: string,
    destination: string
) {
    const id = '_' + randomBytes(21).toString('hex');
    const xml = create({
        'samlp:LogoutRequest': {
            '@xmlns:samlp': XMLNS.SAMLP,
            '@xmlns:saml': XMLNS.SAML,
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

// Creates a LogoutResponse and returns it as a string of xml.
export const create_logout_response = (
    issuer: string,
    in_response_to: string,
    destination: string,
    status = 'urn:oasis:names:tc:SAML:2.0:status:Success'
) => {
    return create({
        'samlp:LogoutResponse': {
            '@Destination': destination,
            '@ID': '_' + randomBytes(21).toString('hex'),
            '@InResponseTo': in_response_to,
            '@IssueInstant': new Date().toISOString(),
            '@Version': '2.0',
            '@xmlns:samlp': XMLNS.SAMLP,
            '@xmlns:saml': XMLNS.SAML,
            'saml:Issuer': issuer,
            'samlp:Status': {
                'samlp:StatusCode': { '@Value': status },
            },
        },
    }).end({ headless: true });
};

// Takes a base64 encoded @key and returns it formatted with newlines and a PEM header according to @type.
// If it already has a PEM header, it will just return the original key.
export const format_pem = (key: string, type: string) => {
    if (
        /-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g.exec(key) !=
        null
    ) {
        return key;
    }
    return (
        `-----BEGIN ${type.toUpperCase()}-----\n` +
        key.match(/.{1,64}/g)?.join('\n') +
        `\n-----END ${type.toUpperCase()}-----`
    );
};

// Takes a compressed/base64 enoded @saml_request and @private_key and signs the request using RSA-SHA256. It returns
// the result as an object containing the query parameters.
export const sign_request = (
    saml_request: string,
    private_key: string,
    relay_state: any,
    response = false
) => {
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
    const relay_state_data =
        relay_state != null
            ? '&RelayState=' + encodeURIComponent(relay_state)
            : '';
    const sigalg_data =
        '&SigAlg=' +
        encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    const sign = createSign('RSA-SHA256');
    sign.update(saml_request_data + relay_state_data + sigalg_data);
    const samlQueryString: any = {};
    if (response) {
        set(samlQueryString, 'SAMLResponse', saml_request);
    } else {
        set(samlQueryString, 'SAMLRequest', saml_request);
    }
    if (relay_state) {
        set(samlQueryString, 'RelayState', relay_state);
    }
    set(
        samlQueryString,
        'SigAlg',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    );
    set(
        samlQueryString,
        'Signature',
        sign.sign(format_pem(private_key, 'PRIVATE KEY'), 'base64')
    );
    return samlQueryString;
};

// Takes a node XMLDom node and gets the attribute value
export const get_attribute_value = function (
    node: Element,
    attributeName: string
) {
    const attributes = node.attributes || [];
    const attribute = filter(attributes, (attr) => {
        return attr.name === attributeName;
    });
    return attribute[0]?.value;
};

// Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
export const check_status_success = (dom: Document) => {
    const status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status');
    if (status.length !== 1) {
        return false;
    }
    const ref = status[0].childNodes || [];
    return some(ref, (status_code) => {
        if ((status_code as Element).attributes !== null) {
            const status = get_attribute_value(status_code as Element, 'Value');
            return status === 'urn:oasis:names:tc:SAML:2.0:status:Success';
        }
    });
};

export const get_status = (dom: Document) => {
    const status_list: { [key: string]: string[] } = {};
    const status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status');
    if (status.length !== 1) {
        return status_list;
    }
    let top_status: any;
    (status[0].childNodes || []).forEach((status_code: any) => {
        if (status_code.attributes !== null) {
            top_status = get_attribute_value(status_code, 'Value');
            if (status_list[top_status] == null) {
                status_list[top_status] = [];
            }
        }
        (status_code.childNodes || []).forEach((sub_status_code: any) => {
            if (sub_status_code?.attributes !== null) {
                const status = get_attribute_value(sub_status_code, 'Value');
                status_list[top_status].push(status);
            }
        });
    });
    return status_list;
};

export const to_error = (err: any) => {
    if (err === null) {
        return null;
    }
    if (!(err instanceof Error)) {
        return new Error(inspect(err));
    }
    return err;
};

// Takes in an XML @dom of an object containing an EncryptedAssertion and attempts to decrypt it
// using the @private_keys in the given order.

// @cb will be called with an error if the decryption fails, or the EncryptedAssertion cannot be
// found. If successful, it will be called with the decrypted data as a string.
// Todo: Remove async dependency by converting it to promises
export const decrypt_assertion = (
    dom: Document,
    private_keys: string[],
    cb: Callback<string>
) => {
    // This is needed because xmlenc sometimes throws an exception, and sometimes calls the passed-in
    // callback.
    cb = wrap(cb, function (fn, err, result) {
        return setTimeout(() => {
            return fn(to_error(err), result as string);
        }, 0);
    });
    try {
        let encrypted_assertion = dom.getElementsByTagNameNS(
            XMLNS.SAML,
            'EncryptedAssertion'
        );
        if (encrypted_assertion.length !== 1) {
            return cb(
                new Error(
                    `Expected 1 EncryptedAssertion; found ${encrypted_assertion.length}.`
                )
            );
        }
        const encrypted_data = encrypted_assertion[0].getElementsByTagNameNS(
            XMLNS.XENC,
            'EncryptedData'
        );
        if (encrypted_data.length !== 1) {
            return cb(
                new Error(
                    `Expected 1 EncryptedData inside EncryptedAssertion; found ${encrypted_data.length}.`
                )
            );
        }
        const encrypted_assertion_string = encrypted_assertion[0].toString();
        const errors: Error[] = [];
        return eachOfSeries(
            private_keys,
            function (private_key, index, cb_e) {
                return decrypt(
                    encrypted_assertion_string,
                    {
                        key: format_pem(private_key, 'PRIVATE KEY'),
                    },
                    function (err, result) {
                        if (err !== null) {
                            if (err !== null) {
                                errors.push(
                                    new Error(`Decrypt failed: ${inspect(err)}`)
                                );
                            }
                            return cb_e();
                        }
                        debug(
                            `Decryption successful with private key #${index}.`
                        );
                        return cb(null, result);
                    }
                );
            },
            function () {
                return cb(
                    new Error(
                        `Failed to decrypt assertion with provided key(s): ${inspect(
                            errors
                        )}`
                    )
                );
            }
        );
    } catch (error) {
        return cb(new Error(`Decrypt failed: ${inspect(error)}`));
    }
};

// Gets the data that is actually signed according to xml-crypto. This function should mirror the way xml-crypto finds
// elements for security reasons.
export const get_signed_data = (doc: Document, sig: SignedXml) => {
    return map(sig.references, (ref) => {
        var i, idAttribute, len, ref1;
        let uri = ref.uri;
        if (uri && uri[0] === '#') {
            uri = uri.substring(1);
        }
        let elem: SelectedValue[] = [];
        if (uri === '') {
            elem = xpath(doc, '//*');
        } else {
            ref1 = ['Id', 'ID'];
            for (i = 0, len = ref1.length; i < len; i++) {
                idAttribute = ref1[i];
                elem = xpath(
                    doc,
                    "//*[@*[local-name(.)='" + idAttribute + "']='" + uri + "']"
                );
                if (elem.length > 0) {
                    break;
                }
            }
        }
        if (!(elem.length > 0)) {
            throw new Error(
                `Invalid signature; must be a reference to '${ref.uri}'`
            );
        }
        return (sig as any).getCanonXml(ref.transforms, elem[0], {
            inclusiveNamespacesPrefixList: ref.inclusiveNamespacesPrefixList,
        });
    });
};

// This checks the signature of a saml document and returns either array containing the signed data if valid, or null
// if the signature is invalid. Comparing the result against null is NOT sufficient for signature checks as it doesn't
// verify the signature is signing the important content, nor is it preventing the parsing of unsigned content.
export const check_saml_signature = (_xml: string, certificate: string) => {
    // xml-crypto requires that whitespace is normalized as such:
    // https://github.com/yaronn/xml-crypto/commit/17f75c538674c0afe29e766b058004ad23bd5136#diff-5dfe38baf287dcf756a17c2dd63483781b53bf4b669e10efdd01e74bcd8e780aL69
    const xml = _xml.replace(/\r\n?/g, '\n');
    const doc = new DOMParser().parseFromString(xml);
    // xpath failed to capture <ds:Signature> nodes of direct descendents of the root.
    // Call documentElement to explicitly start from the root element of the document.
    const signature = xpath(
        doc.documentElement,
        "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    );
    if (signature.length !== 1) {
        return null;
    }
    const sig: any = new SignedXml();
    sig.keyInfoProvider = {
        getKey: function () {
            return format_pem(certificate, 'CERTIFICATE');
        },
    };
    sig.loadSignature(signature[0] as string);
    const valid = sig.checkSignature(xml);
    if (valid) {
        return get_signed_data(doc, sig);
    } else {
        return null;
    }
};

// Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
// InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
// appear to be valid.
export const parse_response_header = (dom: Document): ResponseHeader => {
    let response: HTMLCollectionOf<Element> | never[] = [];
    for (let response_type of ['Response', 'LogoutResponse', 'LogoutRequest']) {
        response = dom.getElementsByTagNameNS(XMLNS.SAMLP, response_type);
        if (response.length > 0) {
            break;
        }
    }
    if (response.length !== 1) {
        throw new Error(`Expected 1 Response; found ${response.length}`);
    }
    const response_header = {
        version: get_attribute_value(response[0], 'Version'),
        destination: get_attribute_value(response[0], 'Destination'),
        in_response_to: get_attribute_value(response[0], 'InResponseTo'),
        id: get_attribute_value(response[0], 'ID'),
    };
    // If no version attribute is supplied, assume v2
    const version = response_header.version || '2.0';
    if (version !== '2.0') {
        throw new Error(`Invalid SAML Version ${version}`);
    }
    return response_header;
};

// Takes in an xml @dom of an object containing a SAML Assertion and returns the NameID. If there is no NameID found,
// it will return null. It will throw an error if the Assertion is missing or does not appear to be valid.
export const get_name_id = (dom: any) => {
    var ref;
    const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const subject = assertion[0].getElementsByTagNameNS(XMLNS.SAML, 'Subject');
    if (subject.length !== 1) {
        throw new Error(`Expected 1 Subject; found ${subject.length}`);
    }
    const nameid = subject[0].getElementsByTagNameNS(XMLNS.SAML, 'NameID');
    if (nameid.length !== 1) {
        return null;
    }
    return nameid[0].firstChild?.data;
};

// Takes in an xml @dom of an object containing a SAML Assertion and returns the SessionIndex. It will throw an error
// if there is no SessionIndex, no Assertion, or the Assertion does not appear to be valid. Optionally you can pass a
// second argument `false` making SessionIndex optional. Doing so returns `null` instead of throwing an Error if the
// SessionIndex attribute does not exist.
export const get_session_info = (dom: Document, index_required = true) => {
    const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const authn_statement = assertion[0].getElementsByTagNameNS(
        XMLNS.SAML,
        'AuthnStatement'
    );
    if (authn_statement.length !== 1) {
        throw new Error(
            `Expected 1 AuthnStatement; found ${authn_statement.length}`
        );
    }
    const info = {
        index: get_attribute_value(authn_statement[0], 'SessionIndex'),
        not_on_or_after: get_attribute_value(
            authn_statement[0],
            'SessionNotOnOrAfter'
        ),
    };
    if (index_required && info.index === null) {
        throw new Error('SessionIndex not an attribute of AuthnStatement.');
    }
    return info;
};

// Takes in an xml @dom of an object containing a SAML Assertion and returns and object containing the attributes
// contained within the Assertion. It will throw an error if the Assertion is missing or does not appear to be valid.
export const parse_assertion_attributes = (dom: Document) => {
    const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion');
    if (assertion.length !== 1) {
        throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
    }
    const attribute_statement = assertion[0].getElementsByTagNameNS(
        XMLNS.SAML,
        'AttributeStatement'
    );
    if (!(attribute_statement.length <= 1)) {
        throw new Error(
            `Expected 1 AttributeStatement inside Assertion; found ${attribute_statement.length}`
        );
    }
    if (attribute_statement.length === 0) {
        return {};
    }
    const attributes = attribute_statement[0].getElementsByTagNameNS(
        XMLNS.SAML,
        'Attribute'
    );
    return reduce(
        attributes,
        (acc: any, attribute) => {
            const attribute_name = get_attribute_value(attribute, 'Name');
            if (attribute_name == null) {
                throw new Error('Invalid attribute without name');
            }
            const attribute_values = attribute.getElementsByTagNameNS(
                XMLNS.SAML,
                'AttributeValue'
            );
            acc[attribute_name] =
                map(
                    attribute_values,
                    (attribute_value) =>
                        (attribute_value.childNodes[0] as any)?.data
                ) || '';
            return acc;
        },
        {}
    ) as { [key: string]: string[] };
};

// Takes in an object containing SAML Assertion Attributes and returns an object with certain common attributes changed
// into nicer names. Attributes that are not expected are ignored, and attributes with more than one value with have
// all values except the first one dropped.
export const pretty_assertion_attributes = (assertion_attributes: {
    [key: string]: any;
}) => {
    const claim_map: { [key: string]: string } = {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
            'email',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname':
            'given_name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': 'upn',
        'http://schemas.xmlsoap.org/claims/CommonName': 'common_name',
        'http://schemas.xmlsoap.org/claims/Group': 'group',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': 'role',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname':
            'surname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier':
            'ppid',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
            'name_id',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod':
            'authentication_method',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid':
            'deny_only_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid':
            'deny_only_primary_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid':
            'deny_only_primary_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid':
            'group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid':
            'primary_group_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid':
            'primary_sid',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname':
            'windows_account_name',
    };
    return chain(assertion_attributes)
        .toPairs()
        .filter(([k, v]) => claim_map[k] !== null && v.length > 0)
        .map(([k, v]) => [claim_map[k], v[0]])
        .fromPairs()
        .value();
};

// takes in an XML string, returns an XML string
// applies all inclusive namespaces for signature assertions onto assertion tag
// used as recommended workaround for xml-crypto library limitation with inclusive namespaces
// see https://github.com/yaronn/xml-crypto/issues/48#issuecomment-129705816
export const add_namespaces_to_child_assertions = (xml_string: string) => {
    const doc = new DOMParser().parseFromString(xml_string);
    const response_elements = doc.getElementsByTagNameNS(
        XMLNS.SAMLP,
        'Response'
    );
    if (response_elements.length !== 1) {
        return xml_string;
    }
    const response_element = response_elements[0];
    const assertion_elements = response_element.getElementsByTagNameNS(
        XMLNS.SAML,
        'Assertion'
    );
    if (assertion_elements.length !== 1) {
        return xml_string;
    }
    const assertion_element = assertion_elements[0];
    const inclusive_namespaces = assertion_element.getElementsByTagNameNS(
        XMLNS.EXC_C14N,
        'InclusiveNamespaces'
    )[0];
    const prefixList = inclusive_namespaces.getAttribute('PrefixList')?.trim();
    const namespaces =
        inclusive_namespaces && prefixList
            ? prefixList.split(' ').map((ns) => `xmlns:${ns}`)
            : reduce(
                  response_element.attributes,
                  (acc: string[], attr) => {
                      if (attr.name.match(/^xmlns:/)) {
                          return [...acc, attr.name];
                      }
                      return acc;
                  },
                  []
              );

    // add the namespaces that are present in response and missing in assertion.
    namespaces.forEach((ns) => {
        if (
            response_element.getAttribute(ns) &&
            !assertion_element.getAttribute(ns)
        ) {
            const new_attribute = doc.createAttribute(ns);
            new_attribute.value = response_element.getAttribute(ns) as string;
            assertion_element.setAttributeNode(new_attribute);
        }
    });
    return new XMLSerializer().serializeToString(response_element);
};

// Takes a DOM of a saml_response, private keys with which to attempt decryption and the
// certificate(s) of the identity provider that issued it and will return a user object containing
// the attributes or an error if keys are incorrect or the response is invalid.
// Todo: Remove async dependency by converting it to promises
export const parse_authn_response = (
    saml_response: Document,
    sp_private_keys: string[],
    idp_certificates: string[],
    allow_unencrypted: boolean,
    ignore_signature: boolean,
    require_session_index: boolean,
    ignore_timing: boolean,
    notbefore_skew: number,
    sp_audience: string,
    cb: any
) => {
    let user: Partial<{
        name_id: string;
        session_index: string;
        session_not_on_or_after: string;
    }> = {};
    return waterfall(
        [
            function (cb_wf: Callback<string>) {
                // Decrypt the assertion
                return decrypt_assertion(
                    saml_response,
                    sp_private_keys,
                    function (err, result) {
                        if (err === null) {
                            return cb_wf(null, result);
                        }
                        if (
                            !(
                                allow_unencrypted &&
                                err?.message ===
                                    'Expected 1 EncryptedAssertion; found 0.'
                            )
                        ) {
                            return cb_wf(err, result);
                        }
                        const assertion = saml_response.getElementsByTagNameNS(
                            XMLNS.SAML,
                            'Assertion'
                        );
                        if (assertion.length !== 1) {
                            return cb_wf(
                                new Error(
                                    `Expected 1 Assertion or 1 EncryptedAssertion; found ${assertion.length}`
                                )
                            );
                        }
                        return cb_wf(null, assertion[0].toString());
                    }
                );
            },
            function (result: string, cb_wf: Callback<Document>) {
                // Validate the signature
                debug(result);
                if (ignore_signature) {
                    return cb_wf(null, new DOMParser().parseFromString(result));
                }
                const saml_response_str = saml_response.toString();
                idp_certificates.forEach((cert, index) => {
                    let signed_data: any[] | null;
                    try {
                        signed_data =
                            check_saml_signature(result, cert) ||
                            check_saml_signature(saml_response_str, cert);
                    } catch (error: any) {
                        return cb_wf(
                            new Error(
                                `SAML Assertion signature check failed! (Certificate \#${
                                    index + 1
                                } may be invalid. ${error.message}`
                            )
                        );
                    }
                    if (signed_data) {
                        signed_data?.forEach((sd) => {
                            const signed_dom = new DOMParser().parseFromString(
                                sd
                            );
                            const assertion = signed_dom.getElementsByTagNameNS(
                                XMLNS.SAML,
                                'Assertion'
                            );
                            if (assertion.length === 1) {
                                return cb_wf(null, signed_dom);
                            }
                            const encryptedAssertion =
                                signed_dom.getElementsByTagNameNS(
                                    XMLNS.SAML,
                                    'EncryptedAssertion'
                                );
                            if (encryptedAssertion.length === 1) {
                                return decrypt_assertion(
                                    saml_response,
                                    sp_private_keys,
                                    function (err, result) {
                                        if (err === null && result) {
                                            return cb_wf(
                                                null,
                                                new DOMParser().parseFromString(
                                                    result
                                                )
                                            );
                                        }
                                        return cb_wf(err);
                                    }
                                );
                            }
                        });
                        return cb_wf(
                            new Error(
                                'Signed data did not contain a SAML Assertion!'
                            )
                        );
                    }
                    // else Cert was not valid, try the next one
                });
                return cb_wf(
                    new Error(
                        `SAML Assertion signature check failed! (checked ${idp_certificates.length} certificate(s))`
                    )
                );
            },
            function (
                decrypted_assertion: Document,
                cb_wf: Callback<Document>
            ) {
                // Validate the assertion conditions
                const conditions = decrypted_assertion.getElementsByTagNameNS(
                    XMLNS.SAML,
                    'Conditions'
                )[0];
                if (conditions !== null) {
                    if (ignore_timing !== true) {
                        for (let attribute of conditions.attributes) {
                            const condition = attribute.name.toLowerCase();
                            if (
                                condition === 'notbefore' &&
                                Date.parse(attribute.value) >
                                    Date.now() + notbefore_skew * 1000
                            ) {
                                return cb_wf(
                                    new SAMLError(
                                        'SAML Response is not yet valid',
                                        {
                                            NotBefore: attribute.value,
                                        }
                                    )
                                );
                            }
                            if (
                                condition === 'notonorafter' &&
                                Date.parse(attribute.value) <= Date.now()
                            ) {
                                return cb_wf(
                                    new SAMLError(
                                        'SAML Response is no longer valid',
                                        {
                                            NotOnOrAfter: attribute.value,
                                        }
                                    )
                                );
                            }
                        }
                    }
                    const audience_restriction =
                        conditions.getElementsByTagNameNS(
                            XMLNS.SAML,
                            'AudienceRestriction'
                        )[0];
                    const audiences =
                        audience_restriction?.getElementsByTagNameNS(
                            XMLNS.SAML,
                            'Audience'
                        ) || [];
                    if (audiences.length > 0) {
                        const validAudience = find(audiences, (audience) => {
                            const audienceValue = (
                                audience.firstChild as any
                            )?.data?.trim() as string;
                            return (
                                !isEmpty(audienceValue?.trim()) &&
                                ((isRegExp(sp_audience) &&
                                    sp_audience.test(audienceValue)) ||
                                    (isString(sp_audience) &&
                                        sp_audience.toLowerCase() ===
                                            audienceValue.toLowerCase()))
                            );
                        });
                        if (validAudience == null) {
                            return cb_wf(
                                new SAMLError(
                                    'SAML Response is not valid for this audience'
                                )
                            );
                        }
                    }
                }
                return cb_wf(null, decrypted_assertion);
            },
            function (
                validated_assertion: Document,
                cb_wf: Callback<typeof user>
            ) {
                var err, session_info;
                try {
                    // Populate attributes
                    session_info = get_session_info(
                        validated_assertion,
                        require_session_index
                    );
                    user.name_id = get_name_id(validated_assertion);
                    user.session_index = session_info.index;
                    if (session_info.not_on_or_after !== null) {
                        user.session_not_on_or_after =
                            session_info.not_on_or_after;
                    }
                    const assertion_attributes =
                        parse_assertion_attributes(validated_assertion);
                    user = extend(
                        user,
                        pretty_assertion_attributes(assertion_attributes)
                    );
                    user = extend(user, {
                        attributes: assertion_attributes,
                    });
                    return cb_wf(null, { user } as any);
                } catch (error) {
                    return cb_wf(error as Error);
                }
            },
        ],
        cb
    );
};

export const parse_logout_request = function (dom: Document) {
    const request = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'LogoutRequest');
    if (request.length !== 1) {
        throw new Error(`Expected 1 LogoutRequest; found ${request.length}`);
    }
    const logOutRequest: Partial<{
        issuer: string;
        name_id: string;
        session_index: string;
    }> = {};
    const issuer = dom.getElementsByTagNameNS(XMLNS.SAML, 'Issuer');
    if (issuer.length === 1) {
        logOutRequest.issuer = (issuer[0].firstChild as any)?.data;
    }
    const name_id = dom.getElementsByTagNameNS(XMLNS.SAML, 'NameID');
    if (name_id.length === 1) {
        logOutRequest.name_id = (name_id[0].firstChild as any)?.data;
    }
    const session_index = dom.getElementsByTagNameNS(
        XMLNS.SAMLP,
        'SessionIndex'
    );
    if (session_index.length === 1) {
        logOutRequest.session_index = (
            session_index[0].firstChild as any
        )?.data;
    }
    return logOutRequest;
};

export const set_option_defaults = (
    request_options: any,
    idp_options: any,
    sp_options: any
) => {
    return defaults({}, request_options, idp_options, sp_options);
};
