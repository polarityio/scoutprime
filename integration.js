'use strict';

let request = require('request');
let _ = require('lodash');
let async = require('async');
let ip = require('ip');
let log = null;

const IP_ICON = '<i class="btb bt-desktop integration-text-bold-color"></i>';
const CIDR_ICON = '<i class="fa fa-fw fa-cogs integration-text-bold-color" ></i>';
const FQDN_ICON = '<i class="fa fa-fw fa-globe integration-text-bold-color" ></i>';
const LOOKUP_BATCH_SIZE = 5;

const ELEMENT_ATTRIBUTES = [
    // "locations",
    // "owners",
    // "sources",
    "threats",
    "tic-score"
];

function startup(logger) {
    log = logger;
}

function doLookup(entities, options, cb) {
    let ipElements = [];
    let cidrElements = [];
    let domainElements = [];
    let entityObjLookup = new Map();
    let lookupResults = [];

    createSession(options, function (err, sessionKey) {
        if (err) {
            cb({
                detail: "Error Creating Session",
                err: err
            });
            destroySession(options, sessionKey);
            return;
        }

        for (let i = 0; i < entities.length; i++) {
            let entityObj = entities[i];

            if (entityObj.isIPv4 && options.lookupIp) {
                entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
                ipElements.push({
                    name: entityObj.value,
                    type: 'ipv4'
                });
            } else if (_isValidCidr(entityObj) && options.lookupCidr) {
                entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
                cidrElements.push({
                    name: entityObj.value,
                    type: 'cidrv4'
                });
            } else if (entityObj.isDomain && options.lookupFqdn) {
                entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
                domainElements.push({
                    name: entityObj.value,
                    type: 'fqdn'
                });
            }
        }

        let ticThreshold = parseInt(options.tic, 10);


        async.parallel({
            ipv4: function (done) {
                _lookupElements(ipElements, entityObjLookup, ticThreshold, options, sessionKey, function (err, results) {
                    if (err) {
                        done(err);
                        return;
                    }

                    done(null, results);
                });
            },
            fqdn: function (done) {
                _lookupElements(domainElements, entityObjLookup, ticThreshold, options, sessionKey, function (err, results) {
                    if (err) {
                        done(err);
                        return;
                    }

                    done(null, results);
                });
            },
            cidr: function (done) {
                _lookupElements(cidrElements, entityObjLookup, ticThreshold, options, sessionKey, function (err, results) {
                    if (err) {
                        done(err);
                        return;
                    }

                    done(null, results);
                });
            }
        }, function (err, results) {
            destroySession(options, sessionKey);

            if (err) {
                cb(err);
            } else {
                log.info({results: results}, 'Lookup Results');

                results.ipv4.forEach(function (result) {
                    lookupResults.push(result);
                });

                results.fqdn.forEach(function (result) {
                    lookupResults.push(result);
                });

                results.cidr.forEach(function (result) {
                    lookupResults.push(result);
                });

                cb(null, lookupResults);
            }
        });
    });
}

function _isValidCidr(entityObj) {
    if (entityObj.types.indexOf('custom.cidr') >= 0 &&
        ip.cidr(entityObj.value) !== null) {
        return true;
    }

    return false;
}

// function that takes the ErrorObject and passes the error message to the notification window
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
};

// function that creates the Json object to be passed to the payload
var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'SP_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
};

var createSession = function (options, cb) {
    let uri = options.url;

    if (options.username.length > 0) {
        uri += '/api/auth/login';
    }
    log.trace({uri: uri}, "What does the URI look like");

    let postData = {"params": {"username": options.username, "password": options.password}};


    request({
        uri: uri,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: postData,
        json: true
    }, function (err, response, body) {
        if (err) {
            cb(err);
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if (response.statusCode === 401) {
            cb(_createJsonErrorPayload("Invalid Credentials, please check your User Name and Password", null, '401', '2A', 'Invalid Credentials', {
                err: err
            }));
            return;
        }

        cb(null, body['result']['e_session-key_s']);
    });
};

function destroySession(options, sessionKey, cb) {

    let uri = options.url + '/api/auth/login';

    request({
        method: 'GET',
        uri: uri,
        headers: {
            'Accept': 'application/json',
            'x-lg-session': sessionKey
        }
    }, function (err, response, body) {
        if (err) {
            if (cb) {
                cb(_createJsonErrorPayload("Session is being Destroyed", body, '401', '2A', 'Session Terminated', {
                    err: err
                }));
                return;
            }
        }

        if (cb) {
            cb(null, null);
        }
    });
}


/**
 * What is considered a miss in LG?
 *
 * @param element
 * @param minimumTicScore
 * @returns {boolean}
 * @private
 */
function _isEmptyElement(element) {
    //if has a tic-score not considered empty
    if(element['tic-score']){
        return false;
    }

    // If any of the attributes are an array and has a length > 0 (i.e., there is data)
    // then return false for this being an empty element.
    for (let i = 0; i < ELEMENT_ATTRIBUTES.length; i++) {
        let attribute = ELEMENT_ATTRIBUTES[i];
        if (Array.isArray(element[attribute]) && element[attribute].length > 0) {
            return false;
        }
    }

    return true;
}

function _meetsTicThreshold(element, minimumTicScore) {
    if (element['tic-score'] !== null &&
        element['tic-score'] > 0 &&
        element['tic-score'] >= minimumTicScore) {
        return true;
    }

    return false;
}

function _lookupElements(elements, entityObjLookup, ticThreshold, options, sessionKey, cb) {
    if (elements.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];
    let uri = options.url + '/api/elements/get';
    let scoutUrl = options.url;

    let bodyData = {
        "params": {
            "elements": elements,
            "attributes": ELEMENT_ATTRIBUTES
        }
    };

    request({
        uri: uri,
        method: 'POST',
        headers: {
            Accept: 'application/json',
            'x-lg-session': sessionKey
        },
        body: bodyData,
        json: true
    }, function (err, response, body) {
        // check for an error
        if (err) {
            cb(err);
            log.error({err: err}, "HTTP Request Error Looking up IPv4");
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if(body.ok !== true){
            // Can happen if a lookup is invalid (e.g., invalid domain)
            cb(null, []);
            return;
        }

        log.debug({body: body}, "Printing out Body");

        body.result.forEach(function (element) {
            if (_isEmptyElement(element)) {
                lookupResults.push({
                    entity: entityObjLookup.get(element.name),
                    data: null
                });
            } else if (_meetsTicThreshold(element, ticThreshold)) {
                lookupResults.push({
                    // Required: This is the entity object passed into the integration doLookup method
                    entity: entityObjLookup.get(element.name),
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        //summary: [IP_ICON + " " + cidrScore + " " + element['tic-score']],
                        summary: ['TIC ' + element['tic-score']],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            ticScore: element['tic-score'],
                            name: element.name,
                            type: element.type,
                            sources: element.sources,
                            threats: element.threats
                        }
                    }
                });
            }
        });

        cb(null, lookupResults);
    });
}

function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)) {
        errors.push({
            key: 'url',
            message: 'You must provide a valid Scout Prime URL'
        })
    }

    if (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide your Scout Prime User Name'
        })
    }

    if (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) {
        errors.push({
            key: 'password',
            message: 'You must provide your Scout Prime Password'
        })
    }

    cb(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};