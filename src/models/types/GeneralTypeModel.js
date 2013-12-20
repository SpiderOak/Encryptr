(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var GeneralTypeModel = Encryptr.prototype.EntryModel.extend({
    displayName: "General",
    defaults: {
      type: "General",
      items: [
        { key: "Text", value: "", placeholder: "Text here" }
      ]
    }
  });

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.GeneralTypeModel = GeneralTypeModel;

})(this, this.console, this.Encryptr);
