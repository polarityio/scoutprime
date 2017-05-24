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
    "locations",
    "owners",
    "sources",
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
                err:err
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
            } else if (entityObj.isDomain && options.lookupDomain) {
                entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
                domainElements.push({
                    name: entityObj.value,
                    type: 'fqdn'
                });
            }
        }

        let ticThreshold = parseInt(options.tic, 10);

        if (ipElements.length > 0) {
            async.parallel({
                ipv4: function (done) {
                    _lookupIPv4Elements(ipElements, entityObjLookup, ticThreshold, options, sessionKey, function (err, results) {
                        if (err) {
                            done(err);
                            return;
                        }

                        done(null, results);
                    });
                }
            }, function (err, results) {
                destroySession(options, sessionKey);

                if(err){
                    cb(err);

                }else{
                    log.info({results:results}, 'Lookup Results');
                    cb(null, results.ipv4);
                }
            });
        }
        //
        // async.each(searchStrings, function (entityObj, next) {
        //         log.debug({entity: entityObj.value}, "logging the value to validate node ip");
        //
        //         _lookupIPv4Elements(ipElements, options, sessionKey, function (err, results) {
        //             if (err) {
        //                 next(err);
        //                 return;
        //             }
        //
        //             if (_doReturnResult('ticScore', results, parseTicOption)) {
        //                 results.forEach(result => {
        //                     lookupResults.push(result);
        //                 });
        //                 log.debug({results: result}, "Results of the IP Query");
        //             }
        //
        //             next(null);
        //         });
        //     } /*else if (_isValidCidr(entityObj) && options.lookupCidr) {
        //      _lookupEntityCidr(entityObj, options, sessionKey, function (err, result) {
        //      if(err){
        //      next(err);
        //      return;
        //      }
        //
        //      if(_doReturnResult('cidr_score', result, parseTicOption)){
        //      lookupResults.push(result);
        //      log.trace({results: result}, "Results of the CIDR Query");
        //      }
        //
        //      next(null);
        //      });
        //      } else if (entityObj.isDomain && options.lookupFqdn) {
        //      _lookupEntityfqdn(entityObj, options, sessionKey, function (err, result) {
        //      if(err){
        //      next(err);
        //      return;
        //      }
        //
        //      if(_doReturnResult('fqdn_score', result, parseTicOption)){
        //      lookupResults.push(result);
        //      log.trace({results: result}, "Results of the FQDN Query");
        //      }
        //
        //      next(null);
        //      });
        //      }*/
            // , function (err) {
            //     if (err) {
            //         cb(err);
            //         destroySession((options, session_key))
            //     } else {
            //         cb(null, lookupResults);
            //     }
            // });
    });
}

function _isValidCidr(entityObj) {
    if (entityObj.types.indexOf('custom.cidr') >= 0 &&
        ip.cidr(entityObj.value) !== null) {
        return true;
    }

    return false;
}

function _doReturnResult(property, result, parseTicOption) {
    if (result.data === null || result.data.details[property] === null) {
        return false;
    }

    if (result.data.details[property] < parseTicOption) {
        return false;
    }

    return true;
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
    // If any of the attributes are an array and has a length > 0 (i.e., there is data)
    // then return false for this being an empty element.
    for(let i=0; i<ELEMENT_ATTRIBUTES.length; i++){
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

function _lookupIPv4Elements(elements, entityObjLookup, ticThreshold, options, sessionKey, cb) {
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

        log.debug({body: body}, "Printing out Body");

        body.result.forEach(function (element) {
            if (_isEmptyElement(element)) {
                lookupResults.push({
                    entity: entityObjLookup.get(element.name),
                    data: null
                });
            } else if(_meetsTicThreshold(element, ticThreshold)){
                lookupResults.push({
                    // Required: This is the entity object passed into the integration doLookup method
                    entity: entityObjLookup.get(element.name),
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [IP_ICON + " " + cidrScore + " " + element['tic-score']],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            ticScore: element['tic-score'],
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


let cidrScore = " TIC Score ";

function _lookupEntityCidr(entityObj, options, session_key, cb) {
    let uri = options.url;


    if (options.username.length > 0) {
        uri += '/api/elements/get';
    }

    let bodyData = {
        "params": {
            "elements": [{
                "name": entityObj.value,
                "type": "cidrv4"
            }],
            "attributes": [
                "owners",
                "sources",
                "threats",
                "tic-score"]
        }
    };

    let scoutUrl = options.url;


    request({
        uri: uri,
        method: 'POST',
        headers: {
            Accept: 'application/json',
            'x-lg-session': session_key
        },
        body: bodyData,
        json: true
    }, function (err, response, body) {
        // check for an error
        if (err) {
            cb(err);
            log.error({err: err}, "Tracing any potential non fatal errors:");
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }


        if (body.result == null) {
            cb(null, {
                entity: entityObj.value,
                data: null
            });

            return;
        }

        log.debug({body: body}, "Printing out Body");


        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // Required: These are the tags that are displayed in your template
                summary: [cidrIcon + " " + cidrScore + " " + result[0]['tic-score']],
                // Data that you want to pass back to the notification window details block
                details: {
                    ticScore: result[0]['tic-score'],
                    cidrData: result[0],
                    cidrUrl: scoutUrl,
                    threats: result[0].threats
                }
            }
        });
    });
}

let fqdnScore = " TIC Score: ";

function _lookupEntityfqdn(entityObj, options, session_key, cb) {
    let uri = options.url;


    if (options.username.length > 0) {
        uri += '/api/elements/get';
    }

    let bodyData = {
        "params": {
            "elements": [{
                "name": entityObj.value,
                "type": "fqdn"
            }],
            "attributes": [
                "owners",
                "sources",
                "threats",
                "tic-score"]
        }
    };

    log.trace({bodyData: bodyData}, "URI looks like in lookupEntity");

    let scoutUrl = options.url;


    request({
        uri: uri,
        method: 'POST',
        headers: {
            Accept: 'application/json',
            'x-lg-session': session_key
        },
        body: bodyData,
        json: true
    }, function (err, response, body) {
        // check for an error
        if (err) {
            cb(err);
            log.error({err: err}, "Logging errors");
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if (body.result == null) {
            cb(null, {
                entity: entityObj.value,
                data: null
            });

            return;
        }

        log.debug({body: body}, "Printing out Body");


        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // Required: These are the tags that are displayed in your template
                summary: [fqdnIcon + " " + fqdnScore + body.result[0]['tic-score']],
                // Data that you want to pass back to the notification window details block
                details: {
                    ticScore: body.result[0]['tic-score'],
                    cidrData: body.result[0],
                    cidrUrl: scoutUrl,
                    threats: body.result[0].threats
                }
            }
        });
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