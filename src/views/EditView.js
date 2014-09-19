(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EditView = Backbone.View.extend({
    events: {
      "submit form": "form_submitHandler"
    },
    initialize: function() {
      _.bindAll(this, "render", "addAll", "addOne", "form_submitHandler",
        "viewActivate", "viewDeactivate");
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      this.model.bind("all", this.addAll, this);
      this.confirmBackNav = {
        title: "Confirm navigation",
        subtitle: "Discard any changes?",
        callback: function() {
          window.app.toastView.show("Changes discarded.");
        }
      };
      this.subViews = [];
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
    },
    render: function() {
      var _this = this;
      this.$el.html(window.tmpl["editView"](this.model.toJSON()));
      window.app.mainView.on("saveentry", this.form_submitHandler, this);
      this.addAll();
      this.$("input").attr("disabled", true);
      return this;
    },
    addAll: function () {
      this.$("ul.editable").html("");
      var _this = this;
      _.each(this.model.toJSON().items, function(item) {
        _this.addOne(item);
      });
    },
    addOne: function(item) {
      var itemModel = new window.Backbone.Model(item);
      var view = new Encryptr.prototype.EditListItemView({
        model: itemModel
      });
      this.$("ul.editable").append("<li class='sep'>" + itemModel.get("key") +
          "</li>");
      this.$("ul.editable").append(view.render().el);
      this.subViews.push(view);
    },
    form_submitHandler: function(event) {
      var _this = this;
      if (event) event.preventDefault();
      if (_this.$('input[name="label"]').val() === "") {
        window.app.toastView.show("The label is required.");
        _this.$('input[name="label"]').css("border","1px solid red");
        return;
      }
      _this.$('input[name="label"]').css("border","none");
      $("input").blur();
      $(".blocker").show();
      var items = _this.model.get("items");
      _.each(_this.$("ul.editable input"), function(input) {
        _.each(items, function(item) {
          if (item.id === input.name) {
            item.value = input.value;
          }
        });
      });
      _this.model.set({
        "label": this.$("input[name=label]").val(),
        items: items
      });
      var indexNeedsUpdate = false;
      if (_this.model.changed.id || _this.model.changed.label ||
              _this.model.changed.type) {
        indexNeedsUpdate = true;
      }
      _this.model.save(null, {
        success: function(model) {
          if (indexNeedsUpdate) {
            window.app.session.load("_encryptrIndex", function(err, container) {
              if (err) {
                window.app.dialogAlertView.show({
                  title: "Error",
                  subtitle: err
                }, function() {
                  window.app.navigator.popView(window.app.defaultPopEffect);
                  $(".blocker").hide();
                });
                return;
              }
              container.keys[model.id] = {
                id: model.id,
                label: model.get("label"),
                type: model.get("type")
              };
              container.save(function(err) {
                if (err) {
                  window.app.dialogAlertView.show({
                    title: "Error",
                    subtitle: err
                  }, function() {
                    window.app.navigator.popView(window.app.defaultPopEffect);
                    $(".blocker").hide();
                  });
                  return;
                }
                window.app.navigator.popView(window.app.defaultPopEffect);
                window.app.toastView.show("Entry saved");
                $(".blocker").hide();
              });
            });
          } else {
            window.app.navigator.popView(window.app.defaultPopEffect);
            window.app.toastView.show("Entry saved");
            $(".blocker").hide();
          }
        },
        error: function(err) {
          $(".blocker").hide();
          window.app.dialogAlertView.show({
            title: "Error",
            subtitle: err
          }, function() {});
        }
      });
    },
    viewActivate: function(event) {
      var _this = this;
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .save-btn").removeClass("hidden");
      window.app.mainView.setTitle(this.model.get("displayName"));
      window.setTimeout(function() {
        _this.$("input").removeAttr("disabled");
        _this.$("input").first().focus();
      }, 100);
    },
    viewDeactivate: function(event) {
      window.app.mainView.backButtonDisplay(false);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn").removeClass("hidden");
      window.app.mainView.setTitle("Encryptr");
      window.app.mainView.off("saveentry", null, null);
      window.app.mainView.off("editentry", null, null);
      window.app.mainView.off("deleteentry", null, null);
    },
    close: function() {
      _.each(this.subViews, function(view) {
        view.close();
      });
      this.remove();
    }
  });
  Encryptr.prototype.EditView = EditView;

  var EditListItemView = Backbone.View.extend({
    tagName: "li",
    className: "input",
    events: {
    },
    initialize: function() {
      _.bindAll(this, "render");
      this.model.bind("change", this.render, this);
    },
    render: function() {
      this.$el.html(
        window.tmpl["editListItemView"](this.model.toJSON())
      );
      return this;
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.EditListItemView = EditListItemView;

})(this, this.console, this.Encryptr);
