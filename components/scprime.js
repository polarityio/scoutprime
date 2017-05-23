'use strict';
polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    ticScore: 0,
    redThreat: '#fa5843',
    greenThreat: '#7dd21b',
    yellowThreat: '#ffc15d',
    threatColor: Ember.computed('details.ticScore', function(){
        let tic = this.get('details.ticScore');
        if(tic >= 75){
            return this.get('redThreat');
        }else if(tic >= 50){
            return this.get('yellowThreat');
        }else{
            return this.get('greenThreat');
        }
    }),
    strokeOffset: Ember.computed('details.ticScore', function(){
        let progress = this.get('details.ticScore') / 100;
        let CIRCUMFERENCE = 2 * Math.PI * 25;
        return CIRCUMFERENCE * (1 - progress);
    })
});