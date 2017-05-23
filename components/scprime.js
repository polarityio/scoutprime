'use strict';
polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    redThreat: '#fa5843',
    greenThreat: '#7dd21b',
    yellowThreat: '#ffc15d',
    /**
     * Radius of the ticScore circle
     */
    radius: 15,
    /**
     * StrokeWidth of the ticScore circle
     */
    strokeWidth: 2,
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
    circumference: Ember.computed('radius', function(){
        return 2 * Math.PI * this.get('radius');
    }),
    strokeOffset: Ember.computed('details.ticScore', function(){
        let progress = this.get('details.ticScore') / 100;
        return this.get('circumference') * (1 - progress);
    })
});