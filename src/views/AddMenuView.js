(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var AddMenuView = Backbone.View.extend({
    className: "addMenu",
    events: {
      "tap a": "a_tapHandler"
    },
    initialize: function() {
      _.bindAll(this, "a_tapHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["addMenuView"]({
        types: Encryptr.prototype.types
      }));
      return this;
    },
    a_tapHandler: function(event) {
      event.stopPropagation();
      event.preventDefault();
      this.dismiss();
      var typeModel = $(event.target).data("model");
      window.app.navigator.pushView(window.app.EditView, {
        model: new window.app.types[typeModel]()
      }, window.app.defaultEffect);
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "-webkit-transform":"scale3d(0.8,0.8,0.8) translate3d(10%,-10%,0)",
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

  Encryptr.prototype.AddMenuView = AddMenuView;

})(this, this.console, this.Encryptr);