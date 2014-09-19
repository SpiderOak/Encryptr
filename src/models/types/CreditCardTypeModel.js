(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var CreditCardType = function() {
    this.type = "Credit Card";
    this.items = [
      { id: "cardType", key: "Type", value: "", placeholder: "Mastercard" },
      { id: "nameOnCard", key: "Name on card", value: "", placeholder: "J Bloggs" },
      { id: "cardNumber", key: "Card Number", value: "", type: "number", placeholder: "123456789012345" },
      { id: "cVV", key: "CVV", value: "", type: "number", placeholder: "123" },
      { id: "expiry", key: "Expiry", value: "", placeholder: "01/15" },
      { id: "notes", key: "Notes", value: "", placeholder: "Notes", type: "textarea" }
    ];
  };

  CreditCardType.prototype.displayName = "Credit Card";
  CreditCardType.prototype.icon = "fa-credit-card";

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.CreditCardType = CreditCardType;

})(this, this.console, this.Encryptr);
