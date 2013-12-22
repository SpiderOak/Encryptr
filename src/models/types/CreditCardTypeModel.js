(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var CreditCardTypeModel = Encryptr.prototype.EntryModel.extend({
    displayName: "Credit Card",
    defaults: {
      type: "Credit Card",
      items: [
        { id: "cardType", key: "Type", value: "", placeholder: "Mastercard" },
        { id: "nameOnCard", key: "Name on card", value: "", placeholder: "J Bloggs" },
        { id: "cardNumber", key: "Card Number", value: "", placeholder: "123456789012345" },
        { id: "cVV", key: "CVV", value: "", placeholder: "123" },
        { id: "expiry", key: "Expiry", value: "", placeholder: "01/15" }
      ]
    }
  });

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.CreditCardTypeModel = CreditCardTypeModel;

})(this, this.console, this.Encryptr);
