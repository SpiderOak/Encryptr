(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntriesView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      // ...
    },
    initialize: function() {
      _.bindAll(this, "render", "addAll", "addOne", "viewActivate", "viewDeactivate");
      this.collection.bind("reset", this.addAll, this);
      this.collection.bind("add", this.addOne, this);
      this.collection.bind("remove", this.addAll, this);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);

      this.subViews = [];
    },
    render: function() {
      this.$el.html(window.tmpl["entriesView"]({}));
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
    },
    viewActivate: function(event) {
      this.collection.fetch();
    },
    viewDeactivate: function(event) {
      // ...
    },
    close: function() {
      _.each(this.subViews, function(view) {
        view.close();
      });
      this.remove();
    }
  });
  Encryptr.prototype.EntriesView = EntriesView;

  var EntriesListItemView = Backbone.View.extend({
    tagName: "li",
    className: "entry",
    events: {
      "click a": "a_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "render");
      this.model.bind("change", this.render, this);
    },
    render: function() {
      this.$el.html(
        window.tmpl["entriesListItemView"](
          this.model.toJSON()
        )
      );
      return this;
    },
    a_clickHandler: function(event) {
      var _this = this;
      if (!$(".menu").hasClass("dismissed") || !$(".addMenu").hasClass("dismissed")) {
        return;
      }
      window.app.navigator.pushView(window.app.EntryView, {
        model: _this.model
      }, window.app.defaultEffect);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.EntriesListItemView = EntriesListItemView;

})(this, this.console, this.Encryptr);