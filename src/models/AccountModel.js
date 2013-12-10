(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var AccountModel = Backbone.Model.extend({
    defaults: {
      username: "",
      password: "",
      session: undefined
    },
    initialize: function() {
      // ...
    }
  });

  Encryptr.prototype.AccountModel = AccountModel;

})(this, this.console, this.Encryptr);