const fs = require("fs");
const request = require("postman-request");
const { getLogger } = require("../logger");
const { NetworkError } = require("./errors");

const {
  request: { ca, cert, key, passphrase, rejectUnauthorized, proxy }
} = require("../config/config");

const { get, map } = require("lodash/fp");
const { parallelLimit } = require("async");

const _configFieldIsValid = (field) => typeof field === "string" && field.length > 0;

const defaults = {
  ...(_configFieldIsValid(ca) && { ca: fs.readFileSync(ca) }),
  ...(_configFieldIsValid(cert) && { cert: fs.readFileSync(cert) }),
  ...(_configFieldIsValid(key) && { key: fs.readFileSync }),
  ...(_configFieldIsValid(passphrase) && { passphrase }),
  ...(_configFieldIsValid(proxy) && { proxy }),
  ...(typeof rejectUnauthorized === "boolean" && { rejectUnauthorized }),
  json: true
};

class PolarityRequest {
  constructor () {
    this.requestWithDefaults = request.defaults(defaults);
  }
  /**
   * Makes a request network request using postman-request.  If the request is an array, it will run the requests in parallel.
   * @param requestOptions  - the request options to pass to postman-request. It will either being an array of requests or a single request.
   * @returns {{Promise<*>} || {Promise<Array<*>>}}- returns a promise that resolves to the response from the request
   */
  async request (requestOptions) {
    const Logger = getLogger();
    Logger.trace({ requestOptions }, "in request");

    return new Promise(async (resolve, reject) => {
      this.requestWithDefaults(requestOptions, (err, response) => {
        Logger.trace({ err, response }, "in request callback");

        if (err) {
          return reject(
            new NetworkError("Unable to complete network request", {
              cause: err,
              requestOptions
            })
          );
        }

        resolve({
          ...response,
          requestOptions
        });
      });
    });
  }

  async runRequestsInParallel (requestsOptions, limit = 10) {
    const Logger = getLogger();

    Logger.trace({ requestsOptions }, "Parallel Requests");

    const unexecutedRequestFunctions = map(
      ({ entity, ...singleRequestOptions }) =>
        async () => {
          Logger.trace({ singleRequestOptions }, "Parallel Requests");
          const result = await this.request(singleRequestOptions);
          return result ? { entity, result } : result;
        },
      requestsOptions
    );

    return parallelLimit(unexecutedRequestFunctions, limit);
  }
}

class AuthenticatedPolarityRequest extends PolarityRequest {
  constructor () {
    super();
  }

  setRequestHeadersAndOptions (requestOptions) {
    const Logger = getLogger();

    this.authorizedRequestOptions = {
      url: requestOptions.url,
      headers: requestOptions.headers
    };

    // Logger.trace({ requestOptions }, "in set request headers and options");
    // Logger.trace(
    //   { authorizedRequestOptions: this.authorizedRequestOptions },
    //   "in set request headers and options"
    // );
  }

  addHeadersToRequests (requestOptions) {
    const Logger = getLogger();
    // Logger.trace({ requestOptions }, 'in add headers');

    Logger.trace({ requestOptions }, "in set request headers and options");
    Logger.trace(
      { authorizedRequestOptions: this.authorizedRequestOptions },
      "in set request headers and options"
    );

    return map((option) => {
      return {
        entity: option.entity,
        method: option.method,
        url: this.authorizedRequestOptions.url + option.path,
        headers: this.authorizedRequestOptions.headers,
        ...(get("body", option) && { body: option.body })
      };
    }, requestOptions);
  }

  async makeAuthenticatedRequest (requestOptions) {
    const Logger = getLogger();

    // if a single request is passed in, we make it an array so that
    //we can use the same code to process the request
    if (!Array.isArray(requestOptions)) {
      requestOptions = [requestOptions];
    }
    Logger.trace({ requestOptions }, "AAAAAA");

    const requestOptionsWithHeaders = this.addHeadersToRequests(requestOptions);

    // Logger.trace({ requestOptionsWithHeaders }, "Making authenticated request");
    return super.runRequestsInParallel(requestOptionsWithHeaders);
  }
}

module.exports = {
  polarityRequest: new PolarityRequest(),
  authenticatedPolarityRequest: new AuthenticatedPolarityRequest()
};
