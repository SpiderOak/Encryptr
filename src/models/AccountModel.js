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
      passphrase: "",
      session: undefined
    },
    initialize: function() {
      this.on("change", this.updateBackboneSession, this);
    },
    updateBackboneSession: function(model,options) {
      Backbone.Session = this.get("session");
    }
  });

  Encryptr.prototype.AccountModel = AccountModel;

})(this, this.console, this.Encryptr);
