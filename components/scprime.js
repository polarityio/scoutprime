'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  owners: Ember.computed.alias('block.data.details.owners'),
  associations: Ember.computed.alias('block.data.details.associations.results'),
  whoisRecord: Ember.computed.alias(
    'block.data.details.whois.result.whois-record.registry-data'
  ),
  whoisRegistrant: Ember.computed.alias(
    'block.data.details.whois.result.whois-record.registry-data.registrant'
  ),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  redThreat: '#fa5843',
  greenThreat: '#7dd21b',
  yellowThreat: '#ffc15d',
  showLocations: false,
  showWhois: false,
  hasLocationData: Ember.computed('block.data.details.owners.[]', function(){
    const owners = this.get('block.data.details.owners');
    return owners.some((owner) => {
      return owner.locations && owner.locations.length > 0;
    });
  }),
  lastActivityAt: Ember.computed(
    'block.data.details.associations.results.[]',
    function () {
      const numResults = this.get('block.data.details.associations.results.length');
      // associations are sorted from oldest to most recent.  To get the most recent association
      // we find the last record in the array.
      const lastActivityAt = this.get(
        `block.data.details.associations.results.${numResults - 1}.lastSeen`
      );
      return lastActivityAt;
    }
  ),
  dnsHistory: Ember.computed('block.data.details', function () {
    const dns = this.get('block.data.details.dns.result');
    if (dns) {
      return dns['dns-history'];
    }
  }),
  ticScore: Ember.computed('block.data.details', function () {
    const owners = this.get('block.data.details.owners');
    let totalTicScore = 0;

    owners.forEach((owner) => {
      totalTicScore += owner.ticScore;
    });

    return totalTicScore;
  }),
  collections: Ember.computed('block.data.details', function () {
    const owners = this.get('block.data.details.owners');

    return owners.reduce((acc, owner) => {
      acc = acc.concat(owner.collections);
      return acc;
    }, []);
  }),
  name: Ember.computed('block.data.details', function () {
    const owners = this.get('block.data.details.owners');

    const name = owners[0].name;
    return name;
  }),
  /**
   * Radius of the ticScore circle
   */
  threatRadius: 15,
  /**
   * StrokeWidth of the ticScore circle
   */
  threatStrokeWidth: 2,
  elementRadius: 20,
  elementStrokeWidth: 4,
  elementColor: Ember.computed('ticScore', function () {
    return this._getThreatColor(this.get('ticScore'));
  }),
  elementStrokeOffset: Ember.computed('ticScore', 'elementCircumference', function () {
    return this._getStrokeOffset(this.get('ticScore'), this.get('elementCircumference'));
  }),
  threatCircumference: Ember.computed('threatRadius', function () {
    return 2 * Math.PI * this.get('threatRadius');
  }),
  elementCircumference: Ember.computed('elementCircumference', function () {
    return 2 * Math.PI * this.get('elementRadius');
  }),
  actions: {
    toggleLocations: function () {
      this.toggleProperty('showLocations');
    },
    toggleWhois: function () {
      this.toggleProperty('showWhois');
    },
    toggleDnsHistory: function () {
      this.toggleProperty('toggleDnsHistory');
    }
  },
  _getStrokeOffset(ticScore, circumference) {
    let progress = ticScore / 100;
    return circumference * (1 - progress);
  },
  _getThreatColor(ticScore) {
    if (ticScore >= 75) {
      return this.get('redThreat');
    } else if (ticScore >= 50) {
      return this.get('yellowThreat');
    } else {
      return this.get('greenThreat');
    }
  },
  _convertToHumanReadable(string) {
    let newString = '';
    // handle known edge cases
    if (string === 'hashs') {
      return 'Hashes';
    }

    string = string.replace(/hashs/gi, 'hashes');
    string = string.replace(/md5s/gi, 'MD5');
    string = string.replace(/sha(\d+)s/gi, 'SHA-$1');

    for (let i = 0; i < string.length; i++) {
      if (i === 0) {
        newString += string[i].toUpperCase();
      } else if (string[i] === '-') {
        newString += ' ';
      } else {
        newString += string[i];
      }
    }
    return newString;
  },
  _getType(value, attribute) {
    // handle date attributes in a special manner
    if (attribute === 'last-seen' || attribute === 'first-seen') {
      return 'date';
    }

    if (Array.isArray(value)) {
      return 'array';
    } else {
      return 'string';
    }
  }
});

// TODO: associations are going to be a list under a tab
