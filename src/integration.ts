import { PolarityRequest, setLogger } from 'polarity-integration-utils';
import type {
  Entity,
  DoLookupUserOptions,
  IntegrationContext,
  DoLookupResult,
  Logger,
  ValidateOptionsUserOptions,
  ValidationError
} from '@polarityio/integration-types';
import type { ScoutPrimeDetails, Owner } from './types/scout-prime';
import { getAssociations, getOwners, getWhois } from './queries';

let logger: Logger;
let request: PolarityRequest;

function startup(log: Logger): void {
  logger = log;
  setLogger(log);
  request = new PolarityRequest();
}

async function doLookup(
  entities: Entity[],
  options: DoLookupUserOptions,
  context: IntegrationContext
): Promise<DoLookupResult> {
  const url = (options.url as string).endsWith('/')
    ? (options.url as string).slice(0, -1)
    : (options.url as string);
  options.url = url;

  logger.trace({ entities }, 'Entities');

  request.userOptions = options;
  request.network = context.network;

  const lookupResults = await Promise.all(
    entities.map(async (entity): Promise<DoLookupResult[number]> => {
      const [associations, whois, owners] = await Promise.all([
        getAssociations(entity, options, request),
        getWhois(entity, options, request),
        getOwners(entity, options, request)
      ]);

      const isInCollection = owners.some(
        (owner: Owner) => Array.isArray(owner.collections) && owner.collections.length > 0
      );
      const hasActiveRisks = Array.isArray(associations.results) && associations.results.length > 0;
      const searchCriteria = (options.searchCriteria as { value: string }).value;

      const responses: ScoutPrimeDetails = {
        entity: { value: entity.value, type: entity.type },
        associations,
        owners,
        whois
      };

      logger.trace(
        { responses },
        'Responses from Scout Prime before filtering based on search criteria'
      );

      if (
        searchCriteria === 'all' ||
        (searchCriteria === 'collections' && isInCollection) ||
        (searchCriteria === 'activeRisks' && hasActiveRisks) ||
        (searchCriteria === 'collectionsOrActiveRisks' && (isInCollection || hasActiveRisks))
      ) {
        return createResultsObject(entity, responses);
      } else {
        return createNoResultsObject(entity);
      }
    })
  );

  logger.trace({ lookupResults }, 'lookupResults from Scout Prime');
  return lookupResults;
}

function createResultsObject(
  entity: Entity,
  apiResponse: ScoutPrimeDetails
): DoLookupResult[number] {
  const summaryTags: string[] = [];
  const owner = apiResponse.owners[0];
  if (owner) {
    summaryTags.push(`TIC SCORE: ${owner.ticScore}`);
  }

  return {
    entity,
    data: {
      summary: summaryTags,
      details: apiResponse
    }
  };
}

function createNoResultsObject(entity: Entity): DoLookupResult[number] {
  return {
    entity,
    data: null
  };
}

function validateOptions(
  userOptions: ValidateOptionsUserOptions,
  context: IntegrationContext
): ValidationError[] {
  const requiredFields: { key: string; message: string }[] = [
    { key: 'url', message: 'You must provide a valid URL' },
    { key: 'apiKey', message: 'You must provide a valid ScoutPrime API Key' }
  ];

  return requiredFields.reduce<ValidationError[]>((acc, { key, message }) => {
    const optionValue = userOptions[key]?.value;
    if (typeof optionValue !== 'string' || optionValue.length === 0) {
      acc.push({ key, message });
    }
    return acc;
  }, []);
}

export { doLookup, startup, validateOptions };
