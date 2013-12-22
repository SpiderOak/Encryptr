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
      "tap .add-btn": "addButton_tapHandler",
      "tap .nav": "menuClose_tapHandler",
      "tap .subviews": "menuClose_tapHandler"
    },
    initialize: function(options) {
      _.bindAll(this,
          "menuButton_tapHandler",
          "backButton_tapHandler",
          "addButton_tapHandler",
          "backButtonDisplay");
      this.menuView = new Encryptr.prototype.MenuView().render();
      this.menuView.dismiss();
      this.addMenuView = new Encryptr.prototype.AddMenuView().render();
      this.addMenuView.dismiss();
      this.$el.append(this.menuView.el);
      this.$el.append(this.addMenuView.el);
    },
    render: function() {
      this.$(".nav").html(
        window.tmpl["navView"]({})
      );
      return this;
    },
    menuButton_tapHandler: function(event) {
      event.preventDefault();
      this.menuView.toggle();
    },
    backButton_tapHandler: function(event) {
      event.preventDefault();
      console.log("back");
      window.app.navigator.popView(window.app.defaultPopEffect);
      // this.backButtonDisplay(false);
    },
    addButton_tapHandler: function(event) {
      if (!this.menuView.$el.hasClass("dismissed")) {
        return;
      }
      event.preventDefault();
      this.addMenuView.toggle();
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
    },
    menuClose_tapHandler: function(event) {
      if (!this.menuView.$el.hasClass("dismissed") &&
          !$(event.target).hasClass("fa-ellipsis-v") &&
          !$(event.target).hasClass("menu-btn")) {
        this.menuView.dismiss();
      }
      if (!this.addMenuView.$el.hasClass("dismissed") &&
          !$(event.target).hasClass("fa-plus") &&
          !$(event.target).hasClass("add-btn")) {
        this.addMenuView.dismiss();
      }
    },
    close: function() {
      this.menuView.close();
      this.addMenuView.close();
    }
  });

  Encryptr.prototype.MainView = MainView;

})(this, this.console, this.Encryptr);