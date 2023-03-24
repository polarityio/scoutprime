"use strict";

const { createResultObject } = require("./src/create-result-object");
const { setLogger, getLogger } = require("./logger");
const { authenticatedPolarityRequest } = require("./src/polarity-request");
const { getElements } = require("./src/get-elements");
const { getSources } = require("./src/get-sources");
const { map, get } = require("lodash/fp");

let Logger = null;

// const IP_ICON = '<i class="btb bt-desktop integration-text-bold-color"></i>';
// const CIDR_ICON = '<i class="fa fa-fw fa-cogs integration-text-bold-color" ></i>';
// const FQDN_ICON = '<i class="fa fa-fw fa-globe integration-text-bold-color" ></i>';
// const LOOKUP_BATCH_SIZE = 5;

const ELEMENT_ATTRIBUTES = [
  // "locations",  //only works for ipv4
  "owners",
  "sources",
  //"threats",  // no longer works for any type
  "tic-score"
];

function startup (logger) {
  Logger = logger;
  setLogger(Logger);
}

async function doLookup (entities, options, cb) {
  const Logger = getLogger();
  let lookupResults = [];

  Logger.trace({ entities }, "Entities");

  authenticatedPolarityRequest.setRequestHeadersAndOptions({
    url: options.url,
    headers: {
      Authorization: `Bearer ${options.apiKey}`
    }
  });

  const elements = await getElements(entities);
  Logger.trace({ elements }, "Elements");

  if (elements) {
    lookupResults = map((element) => createResultObject(element), elements);
    Logger.trace({ lookupResults }, "Lookup Results");
  }

  return cb(null, lookupResults);
}

const onDetails = async (lookupResult, options, cb) => {
  const Logger = getLogger();

  try {
    /*
      the getSources takes a list of entities and builds request options for each entity.
      in this case we will only have single entity available, so we can just put the entity in an array.
    */
    const response = await getSources([lookupResult.entity]);
    Logger.trace({ response }, "sources");

    if (response) {
      /*
       getSource returns an array of results, but in this case it will only ever be a single result,
       so we can just grab the first element.
       */
      const data = get("0", response);
      lookupResult.data.details.sources = {
        results: data.result.body.results
      };
    }

    Logger.trace({ lookupResult }, "lookupResult in onDetails");
    return cb(null, lookupResult.data);
  } catch (err) {
    Logger.error(err);
  }
};
const onMessage = (lookupResult, options, cb) => {
  // go get dns-history 
  // could be a ton of data, so we need to paginate.
  // 208.100.26.245 - has 74k records for dns history.
};

// const getSources = async (entities) => {
//   const Logger = getLogger();
// };

// function doLookup (entities, options, cb) {
//   let ipElements = [];
//   let cidrElements = [];
//   let domainElements = [];
//   let entityObjLookup = new Map();
//   let lookupResults = [];

//   for (let i = 0; i < entities.length; i++) {
//     let entityObj = entities[i];

//     if (entityObj.isIPv4 && options.lookupIp) {
//       entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
//       ipElements.push({
//         name: entityObj.value,
//         type: 'ipv4'
//       });
//     } else if (_isValidCidr(entityObj) && options.lookupCidr) {
//       entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
//       cidrElements.push({
//         name: entityObj.value,
//         type: 'cidrv4'
//       });
//     } else if (entityObj.isDomain && options.lookupFqdn) {
//       entityObjLookup.set(entityObj.value.toLowerCase(), entityObj);
//       domainElements.push({
//         name: entityObj.value,
//         type: 'fqdn'
//       });
//     }
//   }

//   let ticThreshold = parseInt(options.tic, 10);

//   async.parallel(
//     {
//       ipv4: function (done) {
//         _lookupElements(
//           ipElements,
//           entityObjLookup,
//           ticThreshold,
//           options,
//           function (err, results) {
//             if (err) {
//               done(err);
//               return;
//             }

//             done(null, results);
//           }
//         );
//       },
//       fqdn: function (done) {
//         _lookupElements(
//           domainElements,
//           entityObjLookup,
//           ticThreshold,
//           options,
//           function (err, results) {
//             if (err) {
//               done(err);
//               return;
//             }

//             done(null, results);
//           }
//         );
//       },
//       cidr: function (done) {
//         _lookupElements(
//           cidrElements,
//           entityObjLookup,
//           ticThreshold,
//           options,
//           function (err, results) {
//             if (err) {
//               done(err);
//               return;
//             }

//             done(null, results);
//           }
//         );
//       }
//     },
//     function (err, results) {
//       if (err) {
//         cb(err);
//       } else {
//         log.info({ results: results }, 'Lookup Results');

//         results.ipv4.forEach(function (result) {
//           lookupResults.push(result);
//         });

//         results.fqdn.forEach(function (result) {
//           lookupResults.push(result);
//         });

//         results.cidr.forEach(function (result) {
//           lookupResults.push(result);
//         });

//         cb(null, lookupResults);
//       }
//     }
//   );
// }

// function _isValidCidr (entityObj) {
//   if (entityObj.types.indexOf('custom.cidr') >= 0 && ip.cidr(entityObj.value) !== null) {
//     return true;
//   }

//   return false;
// }

// // function that takes the ErrorObject and passes the error message to the notification window
// var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
//   return {
//     errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
//   };
// };

// // function that creates the Json object to be passed to the payload
// var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
//   let error = {
//     detail: msg,
//     status: httpCode.toString(),
//     title: title,
//     code: 'SP_' + code.toString()
//   };

//   if (pointer) {
//     error.source = {
//       pointer: pointer
//     };
//   }

//   if (meta) {
//     error.meta = meta;
//   }

//   return error;
// };

// /**
//  * What is considered a miss in LG?
//  *
//  * @param element
//  * @param minimumTicScore
//  * @returns {boolean}
//  * @private
//  */
// function _isEmptyElement (element) {
//   //if has a tic-score not considered empty
//   if (element['tic-score']) {
//     return false;
//   }

//   // If any of the attributes are an array and has a length > 0 (i.e., there is data)
//   // then return false for this being an empty element.
//   for (let i = 0; i < ELEMENT_ATTRIBUTES.length; i++) {
//     let attribute = ELEMENT_ATTRIBUTES[i];
//     if (Array.isArray(element[attribute]) && element[attribute].length > 0) {
//       return false;
//     }
//   }

//   return true;
// }

// function _meetsTicThreshold (element, minimumTicScore) {
//   if (
//     element['tic-score'] !== null &&
//     element['tic-score'] > 0 &&
//     element['tic-score'] >= minimumTicScore
//   ) {
//     return true;
//   }

//   return false;
// }

// function lookupIP (entity, options, cb) {
//   const query = {
//     query: [
//       'and',
//       ['=', 'left.ipv4', 134744072],
//       ['or', ['=', 'type', 'vulnerable-to'], ['=', 'type', 'associated-with']]
//     ],
//     workspaceIds: ['8O[$+RgJeXJ{W_]3[PaCC}27/'],
//     fields: [
//       'right.description',
//       'right.cvss',
//       'right.classifications',
//       'right.ticScore',
//       'right.threatId',
//       'right.name',
//       'firstSeen',
//       'lastSeen',
//       'meta',
//       'port',
//       'sources',
//       'userUploaded'
//     ],
//     from: 0,
//     limit: 25,
//     sortBy: [['right.ticScore', 'desc']]
//   };
// }

// function _lookupElements (elements, entityObjLookup, ticThreshold, options, cb) {
//   if (elements.length === 0) {
//     cb(null, []);
//     return;
//   }

//   let lookupResults = [];
//   let uri = 'https://pov.sp.lookingglasscyber.com' + '/api/elements/get';
//   let scoutUrl = options.url;

//   let bodyData = {
//     params: {
//       elements: elements,
//       attributes: ELEMENT_ATTRIBUTES
//     }
//   };

//   request(
//     {
//       uri: uri,
//       method: 'POST',
//       headers: {
//         Accept: 'application/json',
//         Authorization: `Bearer ${options.apiKey}`
//       },
//       body: bodyData,
//       json: true
//     },
//     function (err, response, body) {
//       // check for an error
//       if (err) {
//         cb(err);
//         log.error({ err: err }, 'HTTP Request Error Looking up IPv4');
//         return;
//       }

//       if (response.statusCode !== 200) {
//         cb(body);
//         return;
//       }

//       if (body.ok !== true) {
//         // Can happen if a lookup is invalid (e.g., invalid domain)
//         cb(null, []);
//         return;
//       }

//       log.debug({ body: body }, 'Printing out Body');

//       body.result.forEach(function (element) {
//         if (_isEmptyElement(element)) {
//           lookupResults.push({
//             entity: entityObjLookup.get(element.name),
//             data: null
//           });
//         } else if (_meetsTicThreshold(element, ticThreshold)) {
//           lookupResults.push({
//             // Required: This is the entity object passed into the integration doLookup method
//             entity: entityObjLookup.get(element.name),
//             // Required: An object containing everything you want passed to the template
//             data: {
//               // Required: These are the tags that are displayed in your template
//               //summary: [IP_ICON + " " + cidrScore + " " + element['tic-score']],
//               summary: ['TIC ' + element['tic-score']],
//               // Data that you want to pass back to the notification window details block
//               details: {
//                 ticScore: element['tic-score'],
//                 name: element.name,
//                 type: element.type,
//                 sources: element.sources,
//                 owners: element.owners
//                 //threats: element.threats
//               }
//             }
//           });
//         }
//       });

//       cb(null, lookupResults);
//     }
//   );
// }

// function validateOptions (userOptions, cb) {
//   let errors = [];
//   if (
//     typeof userOptions.url.value !== 'string' ||
//     (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)
//   ) {
//     errors.push({
//       key: 'url',
//       message: 'You must provide a valid Scout Prime URL'
//     });
//   }

//   if (
//     typeof userOptions.apiKey.value !== 'string' ||
//     (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
//   ) {
//     errors.push({
//       key: 'apiKey',
//       message: 'You must provide your Scout Prime API Key'
//     });
//   }

//   cb(null, errors);
// }

module.exports = {
  doLookup,
  startup,
  onDetails
  //   validateOptions
};

// I THINK THIS IS USEFUL? I THINK IT'S THE QUERY THAT IS BEING SENT TO SCOUT PRIME.
// https://pov.sp.lookingglasscyber.com/workspace?workspace=Polarity

// {
//   "totalHits": 1,
//   "results": [
//     {
//       "name": "afmgnadzbj.info",
//       "ticScore": 10,
//       "type": "fqdn",
//       "ref": { "type": "fqdn", "id": "afmgnadzbj.info" }
//     }
//   ]
// }

// query
// :
// ["and", ["between", "ticScore", 0, 49], ["=", "collectionIds", ["7g+GrfSvktq+IXB<g/tH>Lh84"]],…]
// 0
// :
// "and"
// 1
// :
// ["between", "ticScore", 0, 49]
// 2
// :
// ["=", "collectionIds", ["7g+GrfSvktq+IXB<g/tH>Lh84"]]
// 3
// :
// ["=", "type", ["asn", "cidrv4", "cidrv6", "fqdn", "ipv4", "ipv6", "owner"]]

// COLLECTIONS API
// https://pov.sp.lookingglasscyber.com/api/v1/workspaces/Polarity/collections
// [
//   {
//     description: 'Collection of indicators used for testing',
//     children: [],
//     ticScore: 10,
//     updatedAt: '2022-09-07T17:58:52.869Z',
//     createdBy: '[Jt]+vqVn2SN=5nx<}S,)0k](',
//     name: 'Polarity Integration Testing',
//     createdAt: '2022-09-07T17:58:52.869Z',
//     updatedBy: '[Jt]+vqVn2SN=5nx<}S,)0k](',
//     id: '7g+GrfSvktq+IXB<g/tH>Lh84'
//   }
// ];
