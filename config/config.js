module.exports = {
  name: 'ScoutPrime',
  acronym: 'SP',
  defaultColor: 'light-blue',
  logging: { level: 'info' },
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
  styles: ['./styles/scprime.less'],
  block: {
    component: {
      file: './components/scprime.js'
    },
    template: {
      file: './templates/scprime.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
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
      key: 'username',
      name: 'User Name',
      description: 'User Name for Scout Prime',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Password',
      description: 'Password for your login to Scout Prime',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'tic',
      name: 'Minimum TIC Score',
      description:
        'Minimum TIC Score to be notified on, values range from 0-100',
      default: '0',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupIp',
      name: 'Lookup IPv4 Addresses',
      description:
        'If checked, the integration will lookup IPv4 addresses in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupCidr',
      name: 'Lookup CIDRs',
      description:
        'If checked, the integration will lookup CIDRs in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupFqdn',
      name: 'Lookup Fully Qualified Domain Names',
      description:
        'If checked, the integration will lookup FQDNs in Scout Prime',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    }
  ]
}
