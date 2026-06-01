import { PolarityRequest } from 'polarity-integration-utils';
import type { Entity, DoLookupUserOptions } from '@polarityio/integration-types';
import type { AssociationsResponse, Owner, WhoisResponse } from './types/scout-prime';

function transformType(entity: Entity): string {
  if (entity.type === 'IPv4') {
    return 'ipv4';
  }

  if (entity.type === 'domain') {
    return 'fqdn';
  }

  if (entity.type === 'IPv4CIDR') {
    return 'cidrv4';
  }

  return entity.type;
}

function buildHeaders(options: DoLookupUserOptions): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    Authorization: `Bearer ${options.apiKey}`
  };
}

export async function getAssociations(
  entity: Entity,
  options: DoLookupUserOptions,
  request: PolarityRequest
): Promise<AssociationsResponse> {
  const type = transformType(entity);

  const response = await request.run({
    method: 'POST',
    url: `${options.url}/api/graph/query`,
    headers: buildHeaders(options),
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
    }
  });

  return response!.body as AssociationsResponse;
}

export async function getWhois(
  entity: Entity,
  options: DoLookupUserOptions,
  request: PolarityRequest
): Promise<WhoisResponse> {
  const response = await request.run({
    method: 'POST',
    url: `${options.url}/api/whois/forward`,
    headers: buildHeaders(options),
    body: {
      params: { domain: entity.value }
    }
  });

  return response!.body as WhoisResponse;
}

export async function getOwners(
  entity: Entity,
  options: DoLookupUserOptions,
  request: PolarityRequest
): Promise<Owner[]> {
  const response = await request.run({
    method: 'POST',
    url: `${options.url}/api/graph`,
    headers: buildHeaders(options),
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

  return response!.body as Owner[];
}
