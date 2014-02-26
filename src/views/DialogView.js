(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var DialogView = Backbone.View.extend({
    className: "modal",
    events: {
      "click .dialog-cancel-btn": "dialogCancelButton_clickHandler",
      "click .dialog-accept-btn": "dialogAcceptButton_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
        "show",
        "toggle",
        "close",
        "dialogCancelButton_clickHandler",
        "dialogAcceptButton_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["dialogView"]({}));
      this.dismiss();
      return this;
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
          "-webkit-transform":"translate3d(0,-100%,0)",
          "opacity":"0"
        }, 100, "linear", function() {
          _this.$el.addClass("dismissed");
        });
        $(document).off("dialogCancel", null, null);
        $(document).off("dialogAccept", null, null);
      }
    },
    show: function(options, callback) {
      var title = options.title || "Confirm";
      var subtitle = options.subtitle || "Are you sure?";
      this.$(".title").html(title);
      this.$(".subtitle").html(subtitle);
      if (this.$el.hasClass("dismissed")) {
        this.$el.removeClass("dismissed");
        this.$("input").removeAttr("disabled");
        this.$(".dialog").animate({
          "-webkit-transform":"translate3d(0,0,0)",
          "opacity":"1"
        }, 100, "linear");
        $(document).on("dialogCancel", callback, this);
        $(document).on("dialogAccept", callback, this);
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

  Encryptr.prototype.DialogView = DialogView;

})(this, this.console, this.Encryptr);
