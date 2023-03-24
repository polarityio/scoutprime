const { get } = require("lodash/fp");
const { getLogger } = require("../logger");

/**
 * Return a Result Object or a Result Miss Object based on the REST API response.
 * @param entity - entity object
 * @param apiResponse - response object from API Rest request
 * @returns {{data: null, entity}|{data: {summary: [string], details}, entity}}
 */
const createResultObject = (response) => {
  if (isMiss(response)) {
    return {
      entity: response.entity,
      data: null
    };
  }

  return {
    entity: response.entity,
    data: {
      summary: createSummaryTags(),
      details: {
        elements: response.result.body
      }
    }
  };
};

const createSummaryTags = (resultsForThisEntity) => {
  const tags = [];
  const Logger = getLogger();

  tags.push(`TEMP TAG CHANGE ME`);

  return tags;
};

/**
 * Okta API returns a 404 status code if a particular IP has no data on it.
 *
 * @param apiResponse
 * @returns {boolean}
 */
const isMiss = (element) => element.result.statusCode === 404;

module.exports = { createResultObject, isMiss };
