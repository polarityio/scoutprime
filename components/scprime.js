"use strict";

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias("block.data.details"),
  sources: Ember.computed.alias("block.data.details.sources.results"),
  timezone: Ember.computed("Intl", function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  redThreat: "#fa5843",
  greenThreat: "#7dd21b",
  yellowThreat: "#ffc15d",
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
  elementColor: Ember.computed("details.ticScore", function () {
    return this._getThreatColor(this.get("details.ticScore"));
  }),
  elementStrokeOffset: Ember.computed("details.ticScore", "elementCircumference", function () {
    return this._getStrokeOffset(this.get("details.ticScore"), this.get("elementCircumference"));
  }),
  //   threats: Ember.computed("details.threats", function () {
  //     let self = this;
  //     let threats = Ember.A();

  //     this.get("details.threats").forEach(function (threat) {
  //       let enrichedThreat = {};
  //       let ticScore = threat["influence-score"];

  //       enrichedThreat.color = self._getThreatColor(ticScore);
  //       enrichedThreat.strokeOffset = self._getStrokeOffset(
  //         ticScore,
  //         self.get("threatCircumference")
  //       );
  //       enrichedThreat.ticScore = ticScore;
  //       enrichedThreat.name = threat["name"];

  //       // We treat these two keys in a special way to ensure they always appear as the last
  //       // two attributes for a threat.
  //       let firstSeen = threat["first-seen"];
  //       let lastSeen = threat["observed-at"];

  //       delete threat["name"];
  //       delete threat["first-seen"];
  //       delete threat["observed-at"];
  //       delete threat["influence-score"];
  //       delete threat["file"];
  //       delete threat["type"];

  //       enrichedThreat.attributes = [];
  //       let rowArray = [];
  //       let keys = Object.keys(threat);

  //       if (firstSeen) {
  //         keys.push("first-seen");
  //       }

  //       if (lastSeen) {
  //         keys.push("last-seen");
  //       }

  //       threat["first-seen"] = firstSeen;
  //       threat["last-seen"] = lastSeen;

  //       for (let i = 0; i < keys.length; i++) {
  //         let key = keys[i];

  //         rowArray.push({
  //           type: self._getType(threat[key], key),
  //           title: self._convertToHumanReadable(key),
  //           value: threat[key]
  //         });

  //         if (rowArray.length === 2) {
  //           enrichedThreat.attributes.push(rowArray);
  //           rowArray = [];
  //         }
  //       }

  //       if (rowArray.length > 0) {
  //         enrichedThreat.attributes.push(rowArray);
  //       }

  //       threats.push(enrichedThreat);
  //     });

  //     return threats;
  //   }),
  threatCircumference: Ember.computed("threatRadius", function () {
    return 2 * Math.PI * this.get("threatRadius");
  }),
  elementCircumference: Ember.computed("elementCircumference", function () {
    return 2 * Math.PI * this.get("elementRadius");
  }),
  /*
     processing source data and setting it on the component, 
     making it easier to access the nested data in the template.
  */
  _processSources () {
    const sources = this.get("sources");

    const sourceNames = sources.map((source) => {
      return {
        sources: source.sources
      };
    });

    const sourceMeta = sources.map((source) => {
      return {
        ports: source.ports,
        etProRiskScore: source.meta.etproRiskScore_ui
      };
    });

    this.set("sourcesNames", sourceNames);
    this.set("sourcesMeta", sourceMeta);

    //                 {
    //               "firstSeen": 1644037687315,
    //               "lastSeen": 1676484483434,
    //               "meta": { "etproRiskScore_ui": 127 },
    //               "sources": ["ETPRO IP Reputation"],
    //               "ref": {
    //                 "type": "associated-with",
    //                 "right": { "type": "threat", "id": ":>g1&269cfSTKtu1v&8s" },
    //                 "left": { "type": "ipv4", "id": 3496221429 }
    //               },
    //               "right": {
    //                 "threatId": ":>g1&269cfSTKtu1v&8s",
    //                 "ticScore": 54,
    //                 "classifications": ["c2", "infrastructure"],
    //                 "name": "Malware Command and Control Server",
    //                 "ref": { "type": "threat", "id": ":>g1&269cfSTKtu1v&8s" }
    //               },
    //               "left": { "ref": { "type": "ipv4", "id": 3496221429 } }
    //             },
  },
  _getStrokeOffset (ticScore, circumference) {
    let progress = ticScore / 100;
    return circumference * (1 - progress);
  },
  _getThreatColor (ticScore) {
    if (ticScore >= 75) {
      return this.get("redThreat");
    } else if (ticScore >= 50) {
      return this.get("yellowThreat");
    } else {
      return this.get("greenThreat");
    }
  },
  _convertToHumanReadable (string) {
    let newString = "";
    // handle known edge cases
    if (string === "hashs") {
      return "Hashes";
    }

    string = string.replace(/hashs/gi, "hashes");
    string = string.replace(/md5s/gi, "MD5");
    string = string.replace(/sha(\d+)s/gi, "SHA-$1");

    for (let i = 0; i < string.length; i++) {
      if (i === 0) {
        newString += string[i].toUpperCase();
      } else if (string[i] === "-") {
        newString += " ";
      } else {
        newString += string[i];
      }
    }
    return newString;
  },
  _getType (value, attribute) {
    // handle date attributes in a special manner
    if (attribute === "last-seen" || attribute === "first-seen") {
      return "date";
    }

    if (Array.isArray(value)) {
      return "array";
    } else {
      return "string";
    }
  }
});
