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
      this.$el.css({"z-index": "10002"});
      this.$el.css({"opacity": 0.7});
      window.setTimeout(function() {
        _this.hide();
      }, 1000);
    },
    hide: function() {
      var _this = this;
      this.$el.css({"opacity": 0});
      window.setTimeout(function(){
        _this.$el.css({"z-index": "-1"});
      }, 510);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.ToastView = ToastView;

})(this, this.console, this.Encryptr);
