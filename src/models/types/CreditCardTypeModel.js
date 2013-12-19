(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var CreditCardTypeModel = Encryptr.prototype.EntryModel.extend({
    defaults: {
      type: "Credit Card",
      items: [
        { key: "Name on card", value: "" },
        { key: "Card Number", value: "" },
        { key: "CVV", value: "" },
        { key: "Expiry", value: "" }
      ]
    }
  });

  Encryptr.prototype.CreditCardTypeModel = CreditCardTypeModel;

})(this, this.console, this.Encryptr);
