import { vi, describe, it, expect, beforeEach } from 'vitest';
import type {
  Entity,
  DoLookupUserOptions,
  ValidateOptionsUserOptions,
  Logger,
  IntegrationContext,
  StandardEntityType
} from '@polarityio/integration-types';
import type {
  AssociationsResponse,
  Owner,
  WhoisResponse
} from '../src/types/scout-prime';

// ── Mocks ───────────────────────────────────────────────────────────────────

const { mockSetLogger, mockGetAssociations, mockGetWhois, mockGetOwners, MockPolarityRequest } =
  vi.hoisted(() => {
    const MockPolarityRequest = vi.fn().mockImplementation(function (this: any) {
      this.userOptions = null;
    });
    return {
      mockSetLogger: vi.fn(),
      mockGetAssociations: vi.fn(),
      mockGetWhois: vi.fn(),
      mockGetOwners: vi.fn(),
      MockPolarityRequest
    };
  });

vi.mock('polarity-integration-utils', () => ({
  PolarityRequest: MockPolarityRequest,
  setLogger: mockSetLogger
}));

vi.mock('../src/queries', () => ({
  getAssociations: mockGetAssociations,
  getWhois: mockGetWhois,
  getOwners: mockGetOwners
}));

// Import AFTER vi.mock()
import { doLookup, startup, validateOptions } from '../src/integration';

// ── Helpers ─────────────────────────────────────────────────────────────────

function createMockLogger(): Logger {
  return {
    trace: vi.fn(),
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    fatal: vi.fn()
  } as unknown as Logger;
}

function createMockContext(): IntegrationContext {
  const createCacheScope = () => ({
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined)
  });
  return {
    cache: {
      global: createCacheScope(),
      integration: createCacheScope(),
      user: createCacheScope()
    },
    integrationId: 'test-integration-id',
    userId: 1,
    logger: createMockLogger(),
    startPolling: vi.fn(),
    stopPolling: vi.fn()
  } as unknown as IntegrationContext;
}

function createEntity(type: StandardEntityType, value: string): Entity {
  const isIPv4 = type === 'IPv4';
  const isDomain = type === 'domain';
  return {
    value,
    rawValue: value,
    displayValue: value,
    types: [type],
    type,
    requestContext: { requestType: 'OnDemand', isUserInitiated: true },
    channels: [],
    longitude: 0,
    latitude: 0,
    IPLong: 0,
    isURL: false,
    isSHA512: false,
    isSHA256: type === 'SHA256',
    isSHA1: type === 'SHA1',
    isPrivateIP: false,
    isMD5: type === 'MD5',
    isIPv6: type === 'IPv6',
    isIPv4,
    isIP: isIPv4 || type === 'IPv6',
    isHex: false,
    isHash: ['MD5', 'SHA1', 'SHA256'].includes(type),
    isHTMLTag: false,
    isEmail: type === 'email',
    isDomain,
    hashType: (type === 'MD5' ? 'MD5' : type === 'SHA1' ? 'SHA1' : type === 'SHA256' ? 'SHA256' : '') as Entity['hashType'],
    IPType: (isIPv4 ? 'IPv4' : type === 'IPv6' ? 'IPv6' : type === 'IPv4CIDR' ? 'IPv4CIDR' : '') as Entity['IPType']
  };
}

function createOptions(overrides: Partial<DoLookupUserOptions> = {}): DoLookupUserOptions {
  return {
    url: 'https://scoutprime.example.com',
    apiKey: 'test-api-key-123',
    searchCriteria: { value: 'all' },
    ...overrides
  };
}

function createMockAssociations(
  results: AssociationsResponse['results'] = []
): AssociationsResponse {
  return { results, total: results.length };
}

function createMockOwner(overrides: Partial<Owner> = {}): Owner {
  return {
    name: 'Test Owner',
    ticScore: 75,
    collections: [],
    owners: [],
    cidrv4s: [],
    cidrv6s: [],
    asns: [],
    locations: [],
    labels: [],
    lastActivityAt: '2024-01-01T00:00:00Z',
    sources: [],
    md5s: [],
    sha1s: [],
    sha256s: [],
    sha512s: [],
    ticHistory7d: [],
    ...overrides
  };
}

function createMockWhois(): WhoisResponse {
  return {
    result: {
      'whois-record': {
        'registry-data': {
          'registrar-name': 'Test Registrar',
          registrant: {
            organization: 'Test Org',
            email: 'admin@example.com',
            telephone: '+1-555-0100',
            fax: '',
            'street-1': '123 Test St',
            city: 'Testville',
            'postal-code': '12345',
            country: 'United States',
            'country-code': 'US'
          }
        }
      }
    }
  };
}

function createMockAssociationResult(): AssociationsResponse['results'][number] {
  return {
    right: {
      description: 'Test vulnerability',
      cvss: 7.5,
      classifications: ['malware'],
      ticScore: 80,
      threatId: 'THREAT-001',
      name: 'Test Threat'
    },
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2024-06-01T00:00:00Z',
    meta: {
      reports_s: '5',
      targets_s: '10',
      targetport_s: '443'
    },
    port: 443,
    sources: ['source1'],
    userUploaded: false
  };
}

// ── Tests ───────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();
  // Initialize the module-scoped logger so doLookup doesn't throw
  startup(createMockLogger());
});

describe('startup', () => {
  it('should call setLogger with the provided logger', () => {
    const logger = createMockLogger();
    startup(logger);
    expect(mockSetLogger).toHaveBeenCalledWith(logger);
  });
});

describe('validateOptions', () => {
  const context = createMockContext();

  it('should return errors when url and apiKey are missing', () => {
    const userOptions: ValidateOptionsUserOptions = {};
    const errors = validateOptions(userOptions, context);

    expect(errors).toHaveLength(2);
    expect(errors).toContainEqual({
      key: 'url',
      message: 'You must provide a valid URL'
    });
    expect(errors).toContainEqual({
      key: 'apiKey',
      message: 'You must provide a valid ScoutPrime API Key'
    });
  });

  it('should return no errors when valid options are provided', () => {
    const userOptions: ValidateOptionsUserOptions = {
      url: {
        key: 'url',
        value: 'https://scoutprime.example.com',
        integration_id: 'test',
        user_can_edit: true,
        admin_only: false
      },
      apiKey: {
        key: 'apiKey',
        value: 'valid-api-key',
        integration_id: 'test',
        user_can_edit: true,
        admin_only: false
      }
    };

    const errors = validateOptions(userOptions, context);
    expect(errors).toHaveLength(0);
  });

  it('should return errors for empty string values', () => {
    const userOptions: ValidateOptionsUserOptions = {
      url: {
        key: 'url',
        value: '',
        integration_id: 'test',
        user_can_edit: true,
        admin_only: false
      },
      apiKey: {
        key: 'apiKey',
        value: '',
        integration_id: 'test',
        user_can_edit: true,
        admin_only: false
      }
    };

    const errors = validateOptions(userOptions, context);
    expect(errors).toHaveLength(2);
    expect(errors).toContainEqual({
      key: 'url',
      message: 'You must provide a valid URL'
    });
    expect(errors).toContainEqual({
      key: 'apiKey',
      message: 'You must provide a valid ScoutPrime API Key'
    });
  });

  it('should return error only for the missing field', () => {
    const userOptions: ValidateOptionsUserOptions = {
      url: {
        key: 'url',
        value: 'https://scoutprime.example.com',
        integration_id: 'test',
        user_can_edit: true,
        admin_only: false
      }
    };

    const errors = validateOptions(userOptions, context);
    expect(errors).toHaveLength(1);
    expect(errors[0].key).toBe('apiKey');
  });
});

describe('doLookup', () => {
  const context = createMockContext();
  const mockWhois = createMockWhois();

  function setupQueryMocks(
    associations: AssociationsResponse,
    owners: Owner[],
    whois: WhoisResponse = mockWhois
  ) {
    mockGetAssociations.mockResolvedValue(associations);
    mockGetOwners.mockResolvedValue(owners);
    mockGetWhois.mockResolvedValue(whois);
  }

  describe('searchCriteria: all', () => {
    it('should return results with data for all entities', async () => {
      const owner = createMockOwner({ ticScore: 85 });
      setupQueryMocks(createMockAssociations(), [owner]);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
      expect(results[0].data!.details).toMatchObject({
        entity: { value: '1.2.3.4', type: 'IPv4' },
        associations: { results: [], total: 0 },
        owners: [owner],
        whois: mockWhois
      });
    });

    it('should return results even with no owners, associations, or whois data', async () => {
      setupQueryMocks(createMockAssociations(), []);

      const entities = [createEntity('domain', 'example.com')];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
    });
  });

  describe('searchCriteria: collections', () => {
    it('should return data when entity is in a collection', async () => {
      const owner = createMockOwner({
        collections: [{ collectionName: 'Important Assets', ticScore: 90 }]
      });
      setupQueryMocks(createMockAssociations(), [owner]);

      const entities = [createEntity('IPv4', '10.0.0.1')];
      const options = createOptions({ searchCriteria: { value: 'collections' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
    });

    it('should return data: null when entity is not in any collection', async () => {
      const owner = createMockOwner({ collections: [] });
      setupQueryMocks(createMockAssociations(), [owner]);

      const entities = [createEntity('IPv4', '10.0.0.1')];
      const options = createOptions({ searchCriteria: { value: 'collections' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).toBeNull();
    });
  });

  describe('searchCriteria: activeRisks', () => {
    it('should return data when entity has active risks', async () => {
      const associations = createMockAssociations([createMockAssociationResult()]);
      setupQueryMocks(associations, [createMockOwner()]);

      const entities = [createEntity('IPv4', '192.168.1.1')];
      const options = createOptions({ searchCriteria: { value: 'activeRisks' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
    });

    it('should return data: null when entity has no active risks', async () => {
      setupQueryMocks(createMockAssociations([]), [createMockOwner()]);

      const entities = [createEntity('IPv4', '192.168.1.1')];
      const options = createOptions({ searchCriteria: { value: 'activeRisks' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).toBeNull();
    });
  });

  describe('searchCriteria: collectionsOrActiveRisks', () => {
    it('should return data when entity is in a collection but has no risks', async () => {
      const owner = createMockOwner({
        collections: [{ collectionName: 'My Collection', ticScore: 50 }]
      });
      setupQueryMocks(createMockAssociations([]), [owner]);

      const entities = [createEntity('domain', 'test.com')];
      const options = createOptions({
        searchCriteria: { value: 'collectionsOrActiveRisks' }
      });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
    });

    it('should return data when entity has active risks but no collections', async () => {
      const associations = createMockAssociations([createMockAssociationResult()]);
      setupQueryMocks(associations, [createMockOwner({ collections: [] })]);

      const entities = [createEntity('domain', 'test.com')];
      const options = createOptions({
        searchCriteria: { value: 'collectionsOrActiveRisks' }
      });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).not.toBeNull();
    });

    it('should return data: null when entity has neither collections nor risks', async () => {
      setupQueryMocks(createMockAssociations([]), [createMockOwner({ collections: [] })]);

      const entities = [createEntity('domain', 'test.com')];
      const options = createOptions({
        searchCriteria: { value: 'collectionsOrActiveRisks' }
      });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(1);
      expect(results[0].data).toBeNull();
    });
  });

  describe('URL trailing slash handling', () => {
    it('should strip trailing slash from URL option', async () => {
      setupQueryMocks(createMockAssociations(), [createMockOwner()]);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({
        url: 'https://scoutprime.example.com/',
        searchCriteria: { value: 'all' }
      });

      await doLookup(entities, options, context);

      // After doLookup, the options.url should have trailing slash stripped
      expect(options.url).toBe('https://scoutprime.example.com');
    });

    it('should not modify URL without trailing slash', async () => {
      setupQueryMocks(createMockAssociations(), [createMockOwner()]);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({
        url: 'https://scoutprime.example.com',
        searchCriteria: { value: 'all' }
      });

      await doLookup(entities, options, context);

      expect(options.url).toBe('https://scoutprime.example.com');
    });
  });

  describe('summary tags', () => {
    it('should include TIC score from first owner in summary', async () => {
      const owner = createMockOwner({ ticScore: 92 });
      setupQueryMocks(createMockAssociations(), [owner]);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      const results = await doLookup(entities, options, context);

      expect(results[0].data!.summary).toContain('TIC SCORE: 92');
    });

    it('should have empty summary when no owners exist', async () => {
      setupQueryMocks(createMockAssociations(), []);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      const results = await doLookup(entities, options, context);

      expect(results[0].data!.summary).toHaveLength(0);
    });
  });

  describe('multiple entities', () => {
    it('should return results for each entity', async () => {
      setupQueryMocks(createMockAssociations(), [createMockOwner()]);

      const entities = [
        createEntity('IPv4', '1.2.3.4'),
        createEntity('domain', 'example.com'),
        createEntity('IPv4', '10.0.0.1')
      ];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      const results = await doLookup(entities, options, context);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result.data).not.toBeNull();
      });
    });

    it('should call query functions once per entity', async () => {
      setupQueryMocks(createMockAssociations(), [createMockOwner()]);

      const entities = [
        createEntity('IPv4', '1.2.3.4'),
        createEntity('domain', 'example.com')
      ];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      await doLookup(entities, options, context);

      expect(mockGetAssociations).toHaveBeenCalledTimes(2);
      expect(mockGetWhois).toHaveBeenCalledTimes(2);
      expect(mockGetOwners).toHaveBeenCalledTimes(2);
    });
  });

  describe('error propagation', () => {
    it('should propagate errors from query functions', async () => {
      mockGetAssociations.mockRejectedValue(new Error('API request failed'));
      mockGetWhois.mockResolvedValue(mockWhois);
      mockGetOwners.mockResolvedValue([createMockOwner()]);

      const entities = [createEntity('IPv4', '1.2.3.4')];
      const options = createOptions({ searchCriteria: { value: 'all' } });

      await expect(doLookup(entities, options, context)).rejects.toThrow(
        'API request failed'
      );
    });
  });
});
