module.exports = {
  name: 'scoutPRIME',
  acronym: 'SP',
  description:
    'Search LookingGlass scoutPRIME for information about IP addresses, domains and CIDR blocks.',
  onDemandOnly: true,
  defaultColor: 'light-gray',
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  logging: { level: 'info' },
  entityTypes: ['IPv4', 'domain', 'IPv4CIDR'],
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
      name: 'scoutPRIME URL',
      description: 'URL for scoutPRIME including scheme (i.e., https://)',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'scoutPRIME API Token',
      description: 'A valid scoutPRIME API Token',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: true
    }
  ]
};
