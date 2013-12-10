(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _           = window._,
    $           = window.Zepto;

  var EntriesCollection = Backbone.Collection.extend({
    initialize: function() {
      this.container = "Entries"; // default
      this.model = Encryptr.prototype.EntryModel; // default
    },
    fetch: function (options) {
      var that = this;
      var container = options && options.container || this.container;
      Backbone.session.load(container, function(err, entries) {
        that.set(
          _.map(entries.keys, function(entry, key){
            return new that.model(entry.attributes);
          })
        );
      });
    }
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);