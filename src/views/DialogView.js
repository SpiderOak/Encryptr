(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var DialogConfirmView = Backbone.View.extend({
    className: "dialogConfirm",
    events: {
      "click": "cancel_clickHandler",
      "click .dialog-cancel-btn": "dialogCancelButton_clickHandler",
      "click .dialog-accept-btn": "dialogAcceptButton_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
        "show",
        "toggle",
        "close",
        "cancel_clickHandler",
        "dialogCancelButton_clickHandler",
        "dialogAcceptButton_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["dialogConfirmView"]({}));
      this.dismiss();
      return this;
    },
    cancel_clickHandler: function(event) {
      if (!$(event.target).hasClass("dialogConfirm")) return;
      this.dismiss();
    },
    dialogCancelButton_clickHandler: function(event) {
      $(document).trigger("dialogCancel");
      this.dismiss();
    },
    dialogAcceptButton_clickHandler: function(event) {
      $(document).trigger("dialogAccept");
      this.dismiss();
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$(".dialog").animate({
          "translate3d":"0,-100%,0",
          "opacity":"0"
        }, 100, "linear", function() {
          _this.$el.addClass("dismissed");
        });
        $(document).off("dialogCancel", null, null);
        $(document).off("dialogAccept", null, null);
      }
    },
    show: function(options, callback) {
      var _this = this;
      var title = options.title || "Confirm";
      var subtitle = options.subtitle || "Are you sure?";
      this.$(".title").html(title);
      this.$(".subtitle").html(subtitle);
      if (this.$el.hasClass("dismissed")) {
        $(document).on("dialogCancel", callback, this);
        $(document).on("dialogAccept", callback, this);
        this.$el.removeClass("dismissed");
        this.$(".dialog").animate({
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
      this.remove();
    }
  });

  Encryptr.prototype.DialogConfirmView = DialogConfirmView;

  var DialogAlertView = Backbone.View.extend({
    className: "dialogAlert",
    events: {
      "click": "cancel_clickHandler",
      "click .dialog-cancel-btn": "dialogCancelButton_clickHandler",
      "click .dialog-accept-btn": "dialogAcceptButton_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
        "show",
        "toggle",
        "close",
        "cancel_clickHandler",
        "dialogAcceptButton_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["dialogAlertView"]({}));
      this.dismiss();
      return this;
    },
    cancel_clickHandler: function(event) {
      if (!$(event.target).hasClass("dialogAlert")) return;
      this.dismiss();
    },
    dialogAcceptButton_clickHandler: function(event) {
      $(document).trigger("dialogAccept");
      this.dismiss();
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$(".dialog").animate({
          "translate3d":"0,-100%,0",
          "opacity":"0"
        }, 100, "linear", function() {
          _this.$el.addClass("dismissed");
        });
        $(document).off("dialogCancel", null, null);
        $(document).off("dialogAccept", null, null);
      }
    },
    show: function(options, callback) {
      var _this = this;
      var title = options.title || "Confirm";
      var subtitle = options.subtitle || "Are you sure?";
      this.$(".title").html(title);
      this.$(".subtitle").html(subtitle);
      if (this.$el.hasClass("dismissed")) {
        if (callback) $(document).on("dialogAccept", callback, this);
        this.$el.removeClass("dismissed");
        this.$(".dialog").animate({
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
      this.remove();
    }
  });

  Encryptr.prototype.DialogAlertView = DialogAlertView;

})(this, this.console, this.Encryptr);
