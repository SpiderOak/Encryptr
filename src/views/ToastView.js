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
      // ...
    },
    initialize: function() {
      _.bindAll(this, "show", "hide");
    },
    render: function() {
      return this;
    },
    show: function(message) {
      var _this = this;
      this.$el.html(message || "done");
      this.$el.css({"opacity": 0.7});
      window.setTimeout(function() {
        _this.hide();
      }, 1000);
    },
    hide: function() {
      this.$el.css({"opacity": 0});
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.ToastView = ToastView;

})(this, this.console, this.Encryptr);