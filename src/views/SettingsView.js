(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  /**
   * Settings view. From here select individual settings pages
   */
  var SettingsView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      "click .change-passphrase": "changePassphrase_clickHandler"
    },
    initialize: function () {
      _.bindAll(this, "render");
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      this.settingsHaveChanged = false;
    },
    render: function () {
      this.$el.html(window.tmpl["settingsView"]({}));
      return this;
    },
    changePassphrase_clickHandler: function(event) {
      event.preventDefault();
      window.app.navigator.pushView(window.app.PassphraseSettingsView, {
        model: window.app.accountModel
      }, window.app.defaultEffect);
    },
    viewActivate: function(event) {
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").addClass("hidden");
      window.app.mainView.setTitle("Settings");
    },
    viewDeactivate: function(event) {
      // ...
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.SettingsView = SettingsView;

  var PassphraseSettingsView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      // ...
    },
    initialize: function () {
      _.bindAll(this, "render");
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      this.confirmBackNav = {
        title: "Confirm navigation",
        subtitle: "Discard any changes?",
        callback: function() {
          window.app.toastView.show("Changes discarded.");
        }
      };
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
    },
    render: function () {
      this.$el.html(window.tmpl["passphraseSettingsView"]({}));
      return this;
    },
    viewActivate: function(event) {
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").addClass("hidden");
      $(".nav .save-btn").removeClass("hidden");
      window.app.mainView.setTitle("Passphrase");
    },
    viewDeactivate: function(event) {
      // ...
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.PassphraseSettingsView = PassphraseSettingsView;

})(this, this.console, this.Encryptr);
