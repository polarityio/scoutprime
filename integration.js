'use strict';

let request = require('request');
let _ = require('lodash');
let async = require('async');
let ip = require('ip');
let log = null;


function startup(logger) {
    log = logger;
}

let ipIcon = '<i class="btb bt-desktop integration-text-bold-color"></i>';
let cidrIcon = '<i class="fa fa-fw fa-cogs integration-text-bold-color" ></i>';
let fqdnIcon = '<i class="fa fa-fw fa-globe integration-text-bold-color" ></i>';

function doLookup(entities, options, cb) {

    let lookupResults = [];

    let parseTicOption = parseInt(options.tic);


    createSession(options, function(err, session_key){
        if(err){
            cb(err);
            destroySession(options, session_key);
            return;
        }


        async.each(entities, function (entityObj, next) {
            log.debug({entity: entityObj.value}, "logging the value to validate node ip");
            if (entityObj.isIPv4) {
                _lookupEntity(entityObj, options, session_key, function (err, result) {
                    if (err) {
                        next(err);
                    } else if(result.data.details.tic_score === null || (parseInt(result.data.details.tic_score) <= parseTicOption)){
                        next(null);
                    }
                    else {
                        lookupResults.push(result); log.trace({results: result}, "Results of the Query");
                        next(null);
                    }
                });
            } else if (entityObj.types.indexOf('custom.cidr') >= 0 && options.lookupCidr) {
                _lookupEntityCidr(entityObj, options, session_key, function (err, result) {
                    if (err) {
                        next(err);
                    } else if (result.data.details.cidr_score === null || (parseInt(result.data.details.cidr_score) <= parseTicOption) && (ip.cidr(entityObj.value) != null)) {
                        next(null);
                    }
                    else {
                        lookupResults.push(result);log.trace({results: result}, "Results of the Query");
                        next(null);
                    }
                });
            } else if (entityObj.isDomain && options.lookupFqdn) {
                _lookupEntityfqdn(entityObj, options, session_key, function (err, result) {
                    if (err) {
                        next(err);
                    } else if (result.data.details.fqdn_score === null || (parseInt(result.data.details.fqdn_score) <= parseTicOption)) {
                        next(null);
                    }
                    else {
                        lookupResults.push(result); log.trace({results: result}, "Results of the Query");
                        next(null);
                    }
                });
            } else {
                lookupResults.push({entity: entityObj, data: null}); //Cache the missed results
                next(null);
            }
        }, function (err) {
        /**
         * The callback should return 3 parameters
         *
         * @parameter as JSON api formatted error message or a string error message, null if there is no error
         *      Any error message returned here is displayed in the notification window for the user that experienced
         *      the error.  This is a good place to return errors related to API authentication or other issues.     *
         * @parameter entitiesWithNoData an Array of entity objects that had no data for them.  This is used by the caching
         * system.
         * @parameter lookupResults An array of lookup result objects
         */
            cb(err, lookupResults);
            destroySession(options,session_key);
        });
    });

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

var createSession = function(options, cb){
    let uri = options.url;

    if (options.username.length > 0){
        uri += '/api/auth/login';
    }
    log.trace({uri:uri}, "What does the URI look like");

    let postData = { "params" : { "username": options.username, "password": options.password}};


    request({
        uri: uri,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: postData,
        json: true
    }, function(err, response, body){
        if (err) {
            cb(err);
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if(response.statusCode === 401){
            cb(_createJsonErrorPayload("Invalid Credentials, please check your User Name and Password", null, '401', '2A', 'Invalid Credentials', {
                err: err
            }));
            return;
        }

        cb(null, body['result']['e_session-key_s']);
    });
};

var destroySession = function(options, session_key, cb){

    var uri = options.url + '/api/auth/login';

    request({
        method: 'GET',
        uri: uri,
        headers: {
            'Accept': 'application/json',
            'x-lg-session': session_key
        }
    }, function(err, response, body) {
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
};


let tScore = " TIC Score ";

function _lookupEntity(entityObj, options, session_key, cb) {
    let uri = options.url;


    if (options.username.length > 0) {
        uri += '/api/search';
    }

    let bodyData = {"e_type_k": "n_ipv4", "query": entityObj.value, "limit": 10};

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
    }, function(err, response, body) {
        // check for an error
        if (err) {
            cb(err);
            log.error({err:err}, "Logging errors");
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if(body.data == null){
            cb(null, {
                entity: entityObj.value,
                data: null
            });

            return;
        }

        let owners = body.data[0].n_owner_S;
        log.trace({body: body}, "Printing out Body");



        var namesOwners = _.reduce(owners, function (reduced, rows) {
            if (!rows) {
                return reduced;
            }
            reduced.owners.push(rows);

            return reduced;
        }, {
            owners: []
        });


        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // Required: These are the tags that are displayed in your template
                summary: [ipIcon + " " + tScore + body.data[0].tic_score_i],
                // Data that you want to pass back to the notification window details block
                details: {
                    tic_score: body.data[0].tic_score_i,
                    ip_ui: body.data[0].n_ipv4_ui,
                    owner: namesOwners.owners,
                    time: body.data[0]['tic_calculated-at_t'],
                    ipUrl: scoutUrl
                }
            }
        });
    });
}


let cidrScore = " TIC Score ";

function _lookupEntityCidr(entityObj, options, session_key, cb) {
    let uri = options.url;


    if (options.username.length > 0) {
        uri += '/api/search';
    }

    let bodyData = {"e_type_k": "n_cidr", "query": entityObj.value, "limit": 10};

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
    }, function(err, response, body) {
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


        if(body.data == null){
            cb(null, {
                entity: entityObj.value,
                data: null
            });

            return;
        }

        log.trace({body: body}, "Printing out Body");

        let owners = body.data[0].n_owner_S;

        let nameOwners = _.reduce(owners, function (reduced, rows) {
            if (!rows) {
                return reduced;
            }
            reduced.owners.push(rows);

            return reduced;
        }, {
            owners: []
        });

        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // Required: These are the tags that are displayed in your template
                summary: [cidrIcon + " " +  cidrScore + " " + body.data[0].tic_score_i],
                // Data that you want to pass back to the notification window details block
                details: {
                    cidr_score: body.data[0].tic_score_i,
                    cidr_s: body.data[0].n_cidr_s,
                    cidrOwner: nameOwners.owners,
                    cTime: body.data[0]['tic_calculated-at_t'],
                    cidrUrl: scoutUrl
                }
            }
        });
    });
}

let fqdnScore = " TIC Score: ";

function _lookupEntityfqdn(entityObj, options, session_key, cb) {
    let uri = options.url;


    if (options.username.length > 0) {
        uri += '/api/search';
    }

    let bodyData = {"e_type_k": "n_fqdn", "query": entityObj.value, "limit": 10};

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
    }, function(err, response, body) {
        // check for an error
        if (err) {
            cb(err);
            log.error({err:err}, "Logging errors");
            return;
        }

        if (response.statusCode !== 200) {
            cb(body);
            return;
        }

        if(body.data == null){
            cb(null, {
                entity: entityObj.value,
                data: null
            });

            return;
        }

        log.debug({body: body}, "Printing out Body");

        let owners = body.data[0].n_owner_S;

        let nameOwners = _.reduce(owners, function (reduced, rows) {
            if (!rows) {
                return reduced;
            }
            reduced.owners.push(rows);

            return reduced;
        }, {
            owners: []
        });


        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
                // Required: This is the entity object passed into the integration doLookup method
                entity: entityObj,
                // Required: An object containing everything you want passed to the template
                data: {
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj.value,
                // Required: These are the tags that are displayed in your template
                summary: [fqdnIcon + " " + fqdnScore + body.data[0].tic_score_i],
                // Data that you want to pass back to the notification window details block
                details: {
                    fqdn_score: body.data[0].tic_score_i,
                    fqdn_s: body.data[0].n_cidr_s,
                    fqdnOwner: nameOwners.owners,
                    fqdnTime: body.data[0]['tic_calculated-at_t'],
                    fqdnUrl: scoutUrl
                }
            }
        });
    });
}

function validateOptions(userOptions, cb) {
    let errors = [];
    if(typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)){
        errors.push({
            key: 'url',
            message: 'You must provide a valid Scout Prime URL'
        })
    }

    if(typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)){
        errors.push({
            key: 'username',
            message: 'You must provide your Scout Prime User Name'
        })
    }

    if(typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)){
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