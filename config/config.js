module.exports = {
  name: 'ScoutPrime',
  acronym: 'SP',
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
  logging: { level: 'trace' },
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
      name: 'ScoutPrime URL',
      description: 'URL for ScoutPrime',
      default: 'https://pov.sp.lookingglasscyber.com',
      type: 'text',
      userCanEdit: true,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'Scout Prime API Key',
      description: 'URL for Scout Prime',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: true
    }
  ]
};
