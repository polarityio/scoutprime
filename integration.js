'use strict';

const { polarityRequest } = require('./src/polarity-request');
const { getDns, getAssociations, getOwners, getWhois } = require('./src/queries');
const { setLogger, getLogger } = require('./src/logger');
const { PolarityResult } = require('./src/create-result-object');
const { map } = require('lodash/fp');
const { parseErrorToReadableJSON } = require('./src/errors');

function startup(logger) {
  setLogger(logger);
}

async function doLookup(entities, options, cb) {
  const Logger = getLogger();

  Logger.trace({ entities }, 'Entities');
  polarityRequest.setOptions(options);

  polarityRequest.setHeaders('Content-Type', 'application/json');
  polarityRequest.setHeaders('Accept', 'application/json');
  polarityRequest.setHeaders('Authorization', `Bearer ${options.apiKey}`);

  try {
    const polarityResult = new PolarityResult();

    const lookupResults = await Promise.all(
      map(async (entity) => {
        const dns = await getDns(entity);
        const associations = await getAssociations(entity);
        const whois = await getWhois(entity);
        const owners = await getOwners(entity);

        const responses = { entity, associations, owners, whois, dns };
        return polarityResult.createResultsObject(responses);
      }, entities)
    );

    Logger.trace({ lookupResults }, 'lookupResults from Scout Prime');
    return cb(null, lookupResults);
  } catch (err) {
    Logger.error({ err }, 'Error in doLookup');
    const error = parseErrorToReadableJSON(err);
    return cb(error);
  }
}

function validateOptions(userOptions, cb) {
  const requiredFields = [
    { key: 'url', message: 'You must provide a valid URL' },
    { key: 'apiKey', message: 'You must provide a valid ScoutPrime API Key' },
    { key: 'username', message: 'You must provide a valid ScoutPrime User Name' },
    { key: 'password', message: 'You must provide a valid ScoutPrime Password' }
  ];

  const errors = requiredFields.reduce((acc, { key, message }) => {
    if (typeof userOptions[key] !== 'string' || userOptions[key].length === 0) {
      acc.push({ key, message });
    }
    return acc;
  }, []);

  return cb(null, errors);
}

module.exports = {
  doLookup,
  validateOptions,
  startup
};
