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
      var _this = this;
      var container = options && options.container || this.container;
      window.app.session.load(container, function(err, entries) {
        _this.set(
          _.map(entries.keys, function(entry, key){
            return new _this.model(entry.attributes);
          })
        );
      });
    }
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);