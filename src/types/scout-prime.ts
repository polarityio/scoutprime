export interface AssociationResult {
  right: {
    description: string;
    cvss: number | null;
    classifications: string[];
    ticScore: number;
    threatId: string;
    name: string;
  };
  firstSeen: string | number;
  lastSeen: string | number;
  meta: {
    reports_s?: string;
    targets_s?: string;
    targetport_s?: string;
  };
  port: number;
  sources: string[];
  userUploaded: boolean;
}

export interface AssociationsResponse {
  results: AssociationResult[];
  total: number;
}

export interface OwnerLocation {
  city: string;
  region: string;
  country: string;
  countryName: string;
  country2Digit: string;
  lastSeen: string | number;
}

export interface OwnerCollection {
  collectionName: string;
  ticScore: number;
}

export interface Owner {
  name: string;
  ticScore: number;
  collections: OwnerCollection[];
  owners: string[];
  cidrv4s: string[];
  cidrv6s: string[];
  asns: number[];
  locations: OwnerLocation[];
  labels: string[];
  lastActivityAt: string | number;
  sources: string[];
  md5s: string[];
  sha1s: string[];
  sha256s: string[];
  sha512s: string[];
  ticHistory7d: number[];
}

export interface WhoisRegistrant {
  organization: string;
  email: string;
  telephone: string;
  fax: string;
  'street-1': string;
  city: string;
  'postal-code': string;
  country: string;
  'country-code': string;
}

export interface WhoisResponse {
  result: {
    'whois-record': {
      'registry-data': {
        'registrar-name': string;
        registrant: WhoisRegistrant;
      };
    };
  };
}

export interface ScoutPrimeDetails {
  entity: {
    value: string;
    type: string;
  };
  associations: AssociationsResponse;
  owners: Owner[];
  whois: WhoisResponse;
}
