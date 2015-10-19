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
      { id: "username", key: "Username", value: "", placeholder: "Login or email address" },
      { id: "password", key: "Password",
        value: Encryptr.prototype.randomString(12), placeholder: "•••••" },
      { id: "url", type: "url", key: "Site URL", value: "",
        placeholder: "e.g. spideroak.com" },
      { id: "notes", key: "Notes", value: "", placeholder: "", type: "textarea" }
    ];
  };

  PasswordType.prototype.displayName = "Password";
  PasswordType.prototype.icon = "fa-key";

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.PasswordType = PasswordType;

})(this, this.console, this.Encryptr);
