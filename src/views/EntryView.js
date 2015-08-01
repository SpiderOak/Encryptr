(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntryView = Backbone.View.extend({
    events: {
      "longTap .copyable": "copyable_longTapHandler",
      "dblclick .copyable": "copyable_doubleTapHandler",
      "click .eye": "eye_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
          "render",
          "editButton_clickHandler",
          "deleteButton_clickHandler",
          "copyable_doubleTapHandler",
          "viewActivate",
          "viewDeactivate");
      this.model.on("change", this.addAll, this);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      window.app.mainView.on("deleteentry", this.deleteButton_clickHandler, this);
      window.app.mainView.once("editentry", this.editButton_clickHandler, this);
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
    },
    render: function() {
      var _this = this;
      this.$el.html(
        window.tmpl["entryView"](
          this.model.toJSON()
        )
      );
      if (this.model.get("items")) {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
      }

      // this.model.fetch();

      return this;
    },
    addAll: function() {
      var _this = this;
      this.$el.html(
        window.tmpl["entryView"](
          this.model.toJSON()
        )
      );
      if (this.model.get("items")) {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
      }
      // Desktop polyfill for longTap
      var timer = null;
      this.$(".copyable").on("mousedown", function(event) {
        timer = setTimeout( function() {
          _this.copyable_longTapHandler(event);
        }, 750 );
      });
      this.$(".copyable").on("mouseup", function(event) {
        clearTimeout( timer );
      });
    },
    copyable_longTapHandler: function(event) {
      event.preventDefault();
      event.stopPropagation();
      var type = $(event.target).attr('data-type');
      var key = _.find(this.model.get("items"), function(item) {
        return item.key === type;
      });
      window.app.copyToClipboard(key.value);
      window.app.toastView.show("Copied to clipboard");
    },
    copyable_doubleTapHandler: function(event) {
      this.copyable_longTapHandler(event);
    },
    eye_clickHandler: function(event) {
      var $this = $(event.target);
      $this.toggleClass('fa-eye');
      $this.toggleClass('fa-eye-slash');
      $this.closest('li').find('.copyable').toggleClass('password');
    },
    editButton_clickHandler: function(event) {
      window.app.navigator.replaceView(
        window.app.EditView,
        {model: this.model},
        window.app.noEffect
      );
    },
    deleteButton_clickHandler: function(event) {
      var _this = this;
      window.app.dialogConfirmView.show({
        title: "Confirm delete",
        subtitle: "Delete this entry?"
      }, function(event) {
        if (event.type === "dialogAccept") {
          $(".blocker").show();
          var oldId = _this.model.id;
          var parentCollection = _this.model.collection;
          _this.model.destroy({success: function(model, response) {
            window.app.session.load("_encryptrIndex", function(err, container) {
              if (err) {
                $(".blocker").hide();
                window.app.dialogAlertView.show({
                  title: "Error",
                  subtitle: err
                }, function(){});
                return;
              }
              delete container.keys[oldId];
              container.save(function(err) {
                if (err) {
                  $(".blocker").hide();
                  window.app.dialogAlertView.show({
                    title: "Error",
                    subtitle: err
                  }, function(){});
                }
                $(".blocker").hide();
                window.app.navigator.popView(window.app.defaultPopEffect);
                window.setTimeout(function(){
                  window.app.toastView.show("Entry deleted");
                }, 100);
                parentCollection.fetch();
              });
            });
          }, error: function(err) {
            window.app.dialogAlertView.show({
              title: "Error",
              subtitle: err
            }, function(){});
            console.error(arguments);
          }});
        }
      });
    },
    viewActivate: function(event) {
      var _this = this;
      _this.model.fetch({success: function() {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
      }, error: function(err) {
        // error out and return to the entries screen
        console.log(err);
      }});
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .edit-btn.right").removeClass("hidden");
      $(".nav .delete-btn").removeClass("hidden");
      window.app.mainView.setTitle(_this.model.get("label"));
    },
    viewDeactivate: function(event) {
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").removeClass("hidden");
      window.app.mainView.setTitle("Encryptr");
      window.app.mainView.off("editentry", null, null);
      window.app.mainView.off("deleteentry", null, null);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.EntryView = EntryView;

})(this, this.console, this.Encryptr);
