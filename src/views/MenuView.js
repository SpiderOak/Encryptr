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
      "click .menu-about": "about_clickHandler",
      "click .menu-logout": "logout_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "settings_clickHandler", "logout_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["menuView"]({}));
      // In case any other views need to log out
      $(document).on("logout", this.logout_clickHandler);
      return this;
    },
    settings_clickHandler: function(event) {
      event.preventDefault();
      window.app.navigator.pushView(window.app.SettingsView, {},
        window.app.defaultEffect);
      this.dismiss();
    },
    logout_clickHandler: function(event) {
      event.preventDefault();
      this.dismiss();
      window.sessionStorage.clear();
      window.app.accountModel.logout(function() {
        window.app.accountModel = new window.app.AccountModel();
        window.app.loginView.disable();
        // Throw up the login screen
        window.app.loginView.show();
        window.setTimeout(function() {
          if (window.app.navigator.viewsStack.length > 0) {
            window.app.navigator.popAll(window.app.noEffect);
          }
          window.app.mainView.close();
        },100);
        window.setTimeout(function() {
          window.app.loginView.enable();
        },350);
      });
    },
    about_clickHandler: function(event) {
      this.dismiss();
      window.app.dialogAlertView.show({
        title: "About Encryptr",
        subtitle: "Encryptr " + window.app.version + "<br>" +
          "(Crypton " + window.crypton.version + ")"
      }, function() {});
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "scale3d":"0.8,0.8,0.8",
          "translate3d":"-10%,-10%,0",
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
          "scale3d":"1,1,1",
          "translate3d":"0,0,0",
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
      $(document).off("logout", this.logout_clickHandler);
      this.remove();
    }
  });

  Encryptr.prototype.MenuView = MenuView;

})(this, this.console, this.Encryptr);
