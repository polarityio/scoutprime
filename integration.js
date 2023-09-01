'use strict';

const { polarityRequest } = require('./src/polarity-request');
const { getAssociations, getOwners, getWhois } = require('./src/queries');
const { setLogger, getLogger } = require('./src/logger');
const { PolarityResult } = require('./src/create-result-object');
const { map } = require('lodash/fp');
const { parseErrorToReadableJSON } = require('./src/errors');

function startup(logger) {
  setLogger(logger);
}

async function doLookup(entities, options, cb) {
  options.url = options.url.endsWith('/') ? options.url.slice(0, -1) : options.url;

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
        // const dns = await getDns(entity);
        const associations = await getAssociations(entity);
        const whois = await getWhois(entity);
        const owners = await getOwners(entity);

        const responses = { entity, associations, owners, whois };

        const isInCollection = owners.some((owner) => {
          return Array.isArray(owner.collections) && owner.collections.length > 0;
        });
        const hasActiveRisks = Array.isArray(associations.results) && associations.results.length > 0;
        const searchCriteria = options.searchCriteria.value;

        Logger.trace({responses}, 'Responses from Scout Prime before filtering based on search criteria');

        if (
          searchCriteria === 'all' ||
          (searchCriteria === 'collections' && isInCollection) ||
          (searchCriteria === 'activeRisks' && hasActiveRisks) ||
          (searchCriteria === 'collectionsOrActiveRisks' &&
            (isInCollection || hasActiveRisks))
        ) {
          return polarityResult.createResultsObject(responses);
        } else {
          return polarityResult.createNoResultsObject(entity);
        }
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
    { key: 'apiKey', message: 'You must provide a valid ScoutPrime API Key' }
  ];

  const errors = requiredFields.reduce((acc, { key, message }) => {
    if (
      typeof userOptions[key].value !== 'string' ||
      userOptions[key].value.length === 0
    ) {
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
