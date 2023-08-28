const { polarityRequest } = require('./polarity-request');
const { getLogger } = require('./logger');

function transformType(entity) {
  if (entity.type === 'IPv4') {
    return 'ipv4';
  }

  if (entity.type === 'domain') {
    return 'fqdn';
  }
}
//TODO: need to fix case of domains causing the integration timeout.
async function getDns(entity) {
  const Logger = getLogger();

  const response = await polarityRequest.send({
    entity,
    method: 'POST',
    path: `api/elements/dns-history`,
    body: {
      params: { name: entity.value, type: transformType(entity), limit: 10 } // change this
    },
    json: true
  });

  Logger.trace({ response }, 'getDns Response from Scout Prime');
  return response[0].result.body;
}

async function getAssociations(entity) {
  const Logger = getLogger();

  Logger.trace({ entity }, 'Entity');

  const type = transformType(entity);

  const response = await polarityRequest.send({
    entity,
    method: 'POST',
    path: `api/graph/query`,
    body: {
      query: [
        'and',
        ['=', `left.${type}`, entity.value],
        ['or', ['=', 'type', 'vulnerable-to'], ['=', 'type', 'associated-with']]
      ],
      fields: [
        'right.description',
        'right.cvss',
        'right.classifications',
        'right.ticScore',
        'right.threatId',
        'right.name',
        'firstSeen',
        'lastSeen',
        'meta',
        'port',
        'sources',
        'userUploaded'
      ],
      from: 0,
      limit: 25,
      sortBy: [['right.ticScore', 'desc']]
    },
    json: true
  });

  Logger.trace({ response }, 'Response from Scout Prime');
  return response[0].result.body;
}

async function getWhois(entity) {
  const Logger = getLogger();

  const response = await polarityRequest.send({
    method: 'POST',
    path: `api/whois/forward`,
    body: {
      params: { domain: entity.value }
    }
  });

  Logger.trace({ response }, 'Response from Scout Prime');
  return response[0].result.body;
}

async function getOwners(entity) {
  const Logger = getLogger();

  const response = await polarityRequest.send({
    entity,
    method: 'POST',
    path: `api/graph`,
    body: {
      fields: [
        'asns',
        'cidrv4s',
        'cidrv6s',
        'collections',
        'labels',
        'lastActivityAt',
        'locations',
        'name',
        'owners',
        'md5s',
        'sha1s',
        'sha256s',
        'sha512s',
        'sources',
        'ticScore',
        'ticHistory7d'
      ],
      refs: [{ id: entity.value, type: transformType(entity) }]
    }
  });

  Logger.trace({ response }, 'Response from Scout Prime');
  return response[0].result.body;
}

module.exports = { getAssociations, getDns, getOwners, getWhois };
