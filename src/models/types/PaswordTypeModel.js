(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var PasswordTypeModel = Encryptr.prototype.EntryModel.extend({
    displayName: "Password",
    defaults: {
      label: "",
      type: "Password",
      items: [
        { id: "username", key: "Username", value: "", placeholder: "Username" },
        { id: "password", key: "Password", value: "", placeholder: "Password" },
        { id: "url", key: "Site URL", value: "", placeholder: "http://www.example.com" }
      ]
    }
  });

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.PasswordTypeModel = PasswordTypeModel;

})(this, this.console, this.Encryptr);
