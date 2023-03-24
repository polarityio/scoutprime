const { map } = require("lodash/fp");
const { getLogger } = require("../logger");
const { authenticatedPolarityRequest } = require("./polarity-request");

const getSources = async (entities) => {
  const Logger = getLogger();

  const requestOptions = map((entity) => {
    return {
      entity,
      method: "POST",
      path: "/api/graph/query",
      body: {
        query: [
          "and",
          ["=", "left.ipv4", `${entity.value}`],
          ["or", ["=", "type", "vulnerable-to"], ["=", "type", "associated-with"]]
        ],
        workspaceIds: ["8O[$+RgJeXJ{W_]3[PaCC}27/"],
        fields: [
          "right.description",
          "right.cvss",
          "right.classifications",
          "right.ticScore",
          "right.threatId",
          "right.name",
          "firstSeen",
          "lastSeen",
          "meta",
          "port",
          "sources",
          "userUploaded"
        ],
        from: 0,
        limit: 25,
        sortBy: [["right.ticScore", "desc"]]
      }
    };
  }, entities);

  Logger.trace({ requestOptions }, "Elements Info Request Options");

  const response = await authenticatedPolarityRequest.makeAuthenticatedRequest(requestOptions);
  Logger.trace({ response }, "Elements Info");

  return response;
};

module.exports = { getSources };
