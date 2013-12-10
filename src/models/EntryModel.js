(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var EntryModel = Backbone.Model.extend({
    // ...
  });

  Encryptr.prototype.EntryModel = EntryModel;

})(this, this.console, this.Encryptr);