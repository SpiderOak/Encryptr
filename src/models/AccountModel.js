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
    },
    logout: function(callback) {
      window.localStorage.setItem("settings",
          JSON.stringify({}));
      this.set("username", "");
      this.set("passphrase", "");
      this.set("session", undefined);
      $(document).trigger('logout');
      window.setTimeout(function() {
        delete window.app.session;
        delete Backbone.session;
      }, 100);
      if (callback) callback();
    }
  });

  Encryptr.prototype.AccountModel = AccountModel;

})(this, this.console, this.Encryptr);
