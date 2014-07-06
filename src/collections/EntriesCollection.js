(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _           = window._,
    $           = window.Zepto;

  var EntriesCollection = Backbone.Collection.extend({
    initialize: function(models, options) {
      this.container = options && options.container || "_encryptrIndex"; // default
      this.model = Encryptr.prototype.EntryModel; // default
    },
    comparator: function(a,b) {
      return a.get('label').localeCompare(b.get('label'));
    },
    fetch: function (options) {
      var _this = this;
      window.app.session.load(this.container, function(err, container) {
        if (options && options.error && err) options.error(err);
        if (err) return;
        _this.reset(
          _.map(container.keys, function(value, key) {
            return new _this.model({
              id: key,
              label: value.label,
              type: value.type
            });
          })
        );
        if (options && options.success) options.success(_this);
      });
    },
    sync: function() {
      // @TODO: EntriesCollection.sync
    }
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);
