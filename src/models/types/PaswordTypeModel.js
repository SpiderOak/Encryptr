(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var PasswordTypeModel = Encryptr.prototype.EntryModel.extend({
    defaults: {
      label: "",
      type: "Password",
      items: [
        { key: "Site URL", value: "" },
        { key: "Username", value: "" },
        { key: "Password", value: "" }
      ]
    }
  });

  Encryptr.prototype.PasswordTypeModel = PasswordTypeModel;

})(this, this.console, this.Encryptr);
