module.exports = {
    "name": "ScoutPrime",
    "acronym": "SP",
    "logging": {level: 'debug'},
    "entityTypes": ['IPv4', 'domain'],
    "customTypes":[
        {
            "key": 'cidr',
            "regex": /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[1-2]?[0-9])/,
            "isCaseSensitive": true,
            "isGlobal": true
        }
    ],
    "styles": [
      "./styles/scprime.less"
    ],
    "block": {
        "component": {
            "file": "./components/scprime.js"
        },
        "template": {
            "file": "./templates/scprime.hbs"
        }
    },
    "options": [
        {
            "key": "url",
            "name": "Scout Prime URL",
            "description": "URL for Scout Prime",
            "default": "",
            "type": "text",
            "userCanEdit": true,
            "adminOnly": true
        },
        {
            "key": "apiKey",
            "name": "API Key",
            "description": "API Key",
            "default": "",
            "type": "password",
            "userCanEdit": false,
            "adminOnly": true
        },
        {
            "key": "tic",
            "name": "Minimum TIC Score",
            "description": "Minimum TIC Score to be notified on, values range from 0-100",
            "default": "0",
            "type": "text",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupIp",
            "name": "Lookup IPv4 Addresses",
            "description": "If checked, the integration will lookup IPv4 addresses in Scout Prime",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupCidr",
            "name": "Lookup CIDRs",
            "description": "If checked, the integration will lookup CIDRs in Scout Prime",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupFqdn",
            "name": "Lookup Fully Qualified Domain Names",
            "description": "If checked, the integration will lookup FQDNs in Scout Prime",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        }
    ]
};