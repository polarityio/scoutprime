module.exports = {
    "name": "ScoutPrime",
    "acronym": "SP",
    "logging": {level: 'debug'},
    "entityTypes": ['IPv4'],
    "customTypes":[
        {
            "key": 'cidr',
            "regex": /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[1-2]?[0-9])/
            //"isCaseSensitive": true,
            //"isGlobal": true
        },
        {
            "key": 'fqdn',
            "regex": /((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}/
            //"isCaseSensitive": false,
            //"isGlobal": true
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
            "key": "username",
            "name": "User Name",
            "description": "User Name for Scout Prime",
            "default": "",
            "type": "text",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "password",
            "name": "Password",
            "description": "Password for your login to Scout Prime",
            "default": "",
            "type": "password",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "tic",
            "name": "Minimum Tic Score",
            "description": "Minimum Tic Score to be notified on",
            "default": "0",
            "type": "text",
            "userCanEdit": true,
            "adminOnly": false
        }
    ]
};