(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntriesView = Backbone.View.extend({
    events: {
      // ...
    },
    initialize: function() {
      _.bindAll(this, "render", "addAll", "addOne");
      this.collection.bind("reset", this.addAll, this);
      this.collection.bind("add", this.addOne, this);
      this.subViews = [];
    },
    render: function() {
      this.$el.html(window.tmpl["entriesView"]({}));
      this.collection.fetch();
      return this;
    },
    addAll: function () {
      this.$("ul").html("");
      this.collection.each(this.addOne);
    },
    addOne: function(model) {
      var view = new Encryptr.prototype.EntriesListItemView({
        model: model
      });
      this.$("ul").append(view.render().el);
      this.subViews.push(view);
    }
  });
  Encryptr.prototype.EntriesView = EntriesView;

  var EntriesListItemView = Backbone.View.extend({
    tagName: "li",
    className: "entry",
    events: {
      "tap a": "a_tapHandler"
    },
    initialize: function() {
      _.bindAll(this, "render");
      this.model.bind("change", this.render);
    },
    render: function() {
      console.log("render");
      this.$el.html(
        window.tmpl["entriesListItemView"](
          this.model.toJSON()
        )
      );
      return this;
    },
    a_tapHandler: function(event) {
      $(".nav .btn.left").toggleClass("hidden");
    }
  });
  Encryptr.prototype.EntriesListItemView = EntriesListItemView;

})(this, this.console, this.Encryptr);