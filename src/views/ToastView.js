(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var ToastView = Backbone.View.extend({
    el: "#toast",
    events: {
      "click": "hide"
    },
    initialize: function() {
      _.bindAll(this, "show", "hide");
    },
    render: function() {
      return this;
    },
    show: function(message, timeout) {
      var _this = this;
      this.$el.html(message || "done");
      this.$el.css({
        "z-index": "10002",
        "opacity": 1,
        "transform": "translate3d(0,54px,0)",
        "-webkit-transform": "translate3d(0,54px,0)"
      });
      window.setTimeout(function() {
        _this.hide();
      }, timeout || 1800);
    },
    hide: function() {
      var _this = this;
      this.$el.css({
        "opacity": 0.01,
        "transform": "translate3d(0,0,0)",
        "-webkit-transform": "translate3d(0,0,0)"
      });
      window.setTimeout(function(){
        _this.$el.css({
          "z-index": "-1"
        });
      }, 600);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.ToastView = ToastView;

})(this, this.console, this.Encryptr);
