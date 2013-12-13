(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var LoginView = Backbone.View.extend({
    el: "#login",
    events: {
      "submit form": "form_submitHandler",
      "tap .loginButton": "loginButton_tapHandler",
      "tap .signupButton": "signupButton_tapHandler"
    },
    init: function() {
      _.bindAll(this,
          "input_focusHandler",
          "input_blurHandler",
          "form_submitHandler",
          "loginButton_tapHandler",
          "signupButton_tapHandler");
      $(document).on("focus", "#login input", this.input_focusHandler);
      $(document).on("blur", "#login input", this.input_blurHandler);
    },
    render: function() {
      return this;
    },
    input_focusHandler: function(event) {
      $(event.target).closest("div.login-input").addClass("focused");
    },
    input_blurHandler: function(event) {
      $(event.target).closest("div.login-input").removeClass("focused");
    },
    form_submitHandler: function(event) {
      var _this = this;
      event.preventDefault();

      var username = $("#username").val().trim();
      var passphrase = $("#passphrase").val();

      $("input").blur();
      
      window.crypton.authorize(username, passphrase, function(err, session) {
        if (err) {
          navigator.notification.alert(err);
        }
        window.app.session = session;
        window.app.session.create("Entries", function(err) {
          window.app.session.load("Entries", function(err, entries) {
            if (err) {
              navigator.notification.alert(err);
              return;
            }
            _this.dismiss();
          });
        });
      });
    },
    loginButton_tapHandler: function(event) {
      event.preventDefault();
      this.form_submitHandler(event);
    },
    signupButton_tapHandler: function(event) {
      navigator.notification.alert("Sign up has not yet been implemented.");
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        this.$("input").attr("disabled", true);
        this.$el.animate({"-webkit-transform":"translate3d(0,100%,0)"}, 100);
        this.$el.addClass("dismissed");
        // Clear username and password values
        this.$("input").val("");
      }
    },
    show: function() {
      if (this.$el.hasClass("dismissed")) {
        this.$("input").removeAttr("disabled");
        this.$el.animate({"-webkit-transform":"translate3d(0,0,0)"}, 100);
        this.$el.removeClass("dismissed");
      }
    }
  });

  Encryptr.prototype.LoginView = LoginView;

})(this, this.console, this.Encryptr);