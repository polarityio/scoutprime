/**
 * Return a Result Object or a Result Miss Object based on the REST API response.
 * @param null || {entity, result}
 * if I pass nothing in, I want it to return a result object with no data
 * if i pass in a single object, I want it to return a result object with data
 * either pass in a single object or an array of objects, being
 * @returns {{data: null, entity}|{data: {summary: [string], details}, entity}}
 *
 */

class PolarityResult {
  createEmptyBlock(entity) {
    return {
      entity: entity,
      data: {
        summary: ['Select a Category'],
        details: []
      }
    };
  }

  createResultsObject(apiResponse) {
    return {
      entity: apiResponse.entity,
      data: {
        summary: createSummaryTags(apiResponse),
        details: apiResponse
      }
    };
  }

  createNoResultsObject() {
    return {
      entity: this.entity,
      data: null
    };
  }
}

const createSummaryTags = (result) => {
  const summaryTags = [];

  const { owners } = result;

  const owner = owners[0];

  summaryTags.push(`TIC SCORE: ${owner.ticScore}`);

  return summaryTags;
};

module.exports = { PolarityResult };
