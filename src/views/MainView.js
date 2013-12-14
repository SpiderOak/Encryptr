(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var MainView = Backbone.View.extend({
    el: "#main",
    events: {
      "tap .menu-btn": "menuButton_tapHandler",
      "tap .back-btn": "backButton_tapHandler",
      "tap .add-btn": "addButton_tapHandler"
    },
    init: function(options) {
      _.bindAll(this,
          "menuButton_tapHandler",
          "backButton_tapHandler",
          "addButton_tapHandler",
          "backbuttonDisplay");
    },
    render: function() {
      this.$(".nav").html(
        window.tmpl["navView"]({})
      );
      return this;
    },
    menuButton_tapHandler: function(event) {
      event.preventDefault();
      console.log("menu");
    },
    backButton_tapHandler: function(event) {
      event.preventDefault();
      console.log("back");
      window.app.navigator.popView(window.app.defaultPopEffect);
    },
    addButton_tapHandler: function(event) {
      console.log("add");
      event.preventDefault();
    },
    setTitle: function(title) {
      this.$(".nav .title").html(title);
    },
    backButtonDisplay: function(show) {
      if (show) {
        this.$(".back-btn").removeClass("hidden");
        this.$(".menu-btn").addClass("hidden");
        return;
      }
      this.$(".back-btn").addClass("hidden");
      this.$(".menu-btn").removeClass("hidden");
    }
  });

  Encryptr.prototype.MainView = MainView;

})(this, this.console, this.Encryptr);