const { map } = require("lodash/fp");
const { getLogger } = require("../logger");
const { authenticatedPolarityRequest } = require("./polarity-request");

const getElements = async (entities) => {
  const Logger = getLogger();

  const requestOptions = map((entity) => {
    return {
      entity,
      method: "POST",
      path: "/api/graph/query",
      body: {
        query: [
          "and",
          [
            "=",
            "type",
            ["asn", "cidrv4", "cidrv6", "fqdn", "ipv4", "ipv6", "owner", "threat", "vulnerability"]
          ],
          `${entity.value}`
        ],
        fields: [
          "labels",
          "locations",
          "name",
          "owners",
          "sources",
          "ticScore",
          "type",
          "userUploaded",
          "cvss"
        ],
        from: 0,
        limit: 50,
        sortBy: [
          ["ticScore", "desc"],
          ["name", "asc"]
        ]
      }
    };
  }, entities);
  Logger.trace({ requestOptions }, "Elements Info Request Options");

  const response = await authenticatedPolarityRequest.makeAuthenticatedRequest(requestOptions);
  Logger.trace({ response }, "Elements Info");

  return response;
};

module.exports = { getElements };
