(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var MenuView = Backbone.View.extend({
    className: "menu",
    events: {
      "tap a": "a_tapHandler"
    },
    initialize: function() {
      _.bindAll(this, "a_tapHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["menuView"]({}));
      return this;
    },
    a_tapHandler: function(event) {
      this.dismiss();
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "-webkit-transform":"scale3d(0.5,0.5,0.5) translate3d(-50%,-50%,0)",
          "opacity":"0"
        }, 100, "linear");
        this.$el.addClass("dismissed");
      }
    },
    show: function() {
      if (this.$el.hasClass("dismissed")) {
        this.$("input").removeAttr("disabled");
        this.$el.animate({
          "-webkit-transform":"scale3d(1,1,1) translate3d(0,0,0)",
          "opacity":"1"
        }, 150, "linear");
        this.$el.removeClass("dismissed");
      }
    },
    toggle: function() {
      if (this.$el.hasClass("dismissed")) {
        this.show();
      } else {
        this.dismiss();
      }
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.MenuView = MenuView;

})(this, this.console, this.Encryptr);