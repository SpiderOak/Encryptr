(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var EntriesCollection = Backbone.Collection.extend({
    // ...
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);