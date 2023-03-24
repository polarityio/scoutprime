module.exports = {
  name: 'ScoutPrime',
  acronym: 'SP',
  logging: { level: 'trace' },
  entityTypes: ['IPv4', 'domain'],
  customTypes: [
    {
      key: 'cidr',
      regex:
        /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[1-2]?[0-9])/,
      isCaseSensitive: true,
      isGlobal: true
    }
  ],
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    // If set to false, the integration will ignore SSL errors.  This will allow the integration to connect
    // to servers without valid SSL certificates.  Please note that we do NOT recommending setting this
    // to false in a production environment.
    rejectUnauthorized: true
  },
  styles: ['./styles/scprime.less'],
  block: {
    component: {
      file: './components/scprime.js'
    },
    template: {
      file: './templates/scprime.hbs'
    }
  },
  options: [
    {
      key: 'url',
      name: 'Scout Prime URL',
      description: 'URL for Scout Prime',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description: 'API Key',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'tic',
      name: 'Minimum TIC Score',
      description: 'Minimum TIC Score to be notified on, values range from 0-100',
      default: '0',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupIp',
      name: 'Lookup IPv4 Addresses',
      description: 'If checked, the integration will lookup IPv4 addresses in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupCidr',
      name: 'Lookup CIDRs',
      description: 'If checked, the integration will lookup CIDRs in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupFqdn',
      name: 'Lookup Fully Qualified Domain Names',
      description: 'If checked, the integration will lookup FQDNs in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    }
  ]
};