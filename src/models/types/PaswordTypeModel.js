(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var PasswordType = function() {
    this.type = "Password";
    this.items = [
      { id: "username", key: "Username", value: "", placeholder: "Username" },
      { id: "password", key: "Password",
        value: Encryptr.prototype.randomString(12), placeholder: "Password" },
      { id: "url", key: "Site URL", value: "",
        placeholder: "http://www.example.com" }
    ];
  };

  PasswordType.prototype.displayName = "Password";

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.PasswordType = PasswordType;

})(this, this.console, this.Encryptr);
