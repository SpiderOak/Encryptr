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
      "click .menu-settings": "settings_clickHandler",
      "click .menu-logout": "logout_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "settings_clickHandler", "logout_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["menuView"]({}));
      return this;
    },
    settings_clickHandler: function(event) {
      this.dismiss();
    },
    logout_clickHandler: function(event) {
      event.preventDefault();
      window.app.loginView.disable();
      this.dismiss();
      // Throw up the login screen
      window.app.loginView.show();
      window.setTimeout(function() {
        delete window.app.session;
        window.app.navigator.popAll(window.app.noEffect);
        window.app.mainView.close();
      },100);
      window.setTimeout(function() {
        window.app.loginView.enable();
      },350);
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "-webkit-transform":"scale3d(0.8,0.8,0.8) translate3d(-10%,-10%,0)",
          "opacity":"0"
        }, 100, "linear", function() {
          _this.$el.addClass("dismissed");
        });
      }
    },
    show: function() {
      if (this.$el.hasClass("dismissed")) {
        this.$el.removeClass("dismissed");
        this.$("input").removeAttr("disabled");
        this.$el.animate({
          "-webkit-transform":"scale3d(1,1,1) translate3d(0,0,0)",
          "opacity":"1"
        }, 100, "linear");
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