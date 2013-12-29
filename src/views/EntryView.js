(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntryView = Backbone.View.extend({
    events: {
      // ...
    },
    initialize: function() {
      this.model.bind("change", this.render, this);
      _.bindAll(this, "render", "editButton_tapHandler", "viewActivate", "viewDeactivate");
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
    },
    render: function() {
      this.$el.html(
        window.tmpl["entryView"](
          this.model.toJSON()
        )
      );
      $(".nav .edit-btn").on("tap", this.editButton_tapHandler);
      return this;
    },
    editButton_tapHandler: function(event) {
      window.app.navigator.replaceView(
        window.app.EditView,
        {model: this.model},
        window.app.noEffect
      );
    },
    viewActivate: function(event) {
      var _this = this;
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .edit-btn.right").removeClass("hidden");
      window.app.mainView.setTitle(this.model.get("label"));
    },
    viewDeactivate: function(event) {
      window.app.mainView.backButtonDisplay(false);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").removeClass("hidden");
      window.app.mainView.setTitle("Encryptr");
    },
    close: function() {
      $(".nav .edit-btn").off("tap", this.editButton_tapHandler);
      this.remove();
    }
  });
  Encryptr.prototype.EntryView = EntryView;

})(this, this.console, this.Encryptr);