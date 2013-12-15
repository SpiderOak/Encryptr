(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var SignupView = Backbone.View.extend({
    className: "signup",
    events: {
      "submit form": "form_submitHandler",
      "tap .signupButton": "signupButton_tapHandler",
      "tap a.backToLogin": "backToLogin_tapHandler"
    },
    initialize: function() {
      _.bindAll(this,
          "input_focusHandler",
          "input_blurHandler",
          "form_submitHandler",
          "signupButton_tapHandler",
          "backToLogin_tapHandler");
      $(document).on("focus", ".signup input", this.input_focusHandler);
      $(document).on("blur", ".signup input", this.input_blurHandler);
    },
    render: function() {
      this.$el.html(window.tmpl["signupView"]({}));
      $(".main").append(this.el);
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

      var username = $("#newusername").val().trim();
      var passphrase = $("#newpassphrase").val();

      $("input").blur();

      window.crypton.generateAccount(username, passphrase, function(err, account) {
        if (err) {
          navigator.notification.alert(
            err,
            function() {},
            "Signup error");
            return;
        }
        // Now log in...
        window.crypton.authorize(username, passphrase, function(err, session) {
          if (err) {
            navigator.notification.alert(
              err,
              function() {},
              "Authentication error");
            return;
          }
          window.app.session = session;
          window.app.session.create("entries", function(err, entries){
            if (err) {
              navigator.notification.alert(err);
              return;
            }
            // Push a ListView 
            window.app.navigator.pushView(
              window.app.EntriesView,
              { collection: new window.app.EntriesCollection() },
              window.app.noEffect
            );
            window.app.loginView.dismiss();
            _this.dismiss();
          });
        });
      });
    },
    signupButton_tapHandler: function(event) {
      event.preventDefault();
      this.form_submitHandler(event);
    },
    backToLogin_tapHandler: function(event) {
      // window.app.loginView.show();
      window.app.loginView.enable();
      this.dismiss();
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
        this.$el.animate({"-webkit-transform":"translate3d(0,0,0)"}, 250);
        this.$el.removeClass("dismissed");
      }
    }
  });

  Encryptr.prototype.SignupView = SignupView;

})(this, this.console, this.Encryptr);