(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var MenuView = Backbone.View.extend({
    className: "menu",
    events: {
      "click .menu-settings": "settings_clickHandler",
      "click .menu-about": "about_clickHandler",
      "click .menu-migrate-beta2": "importBeta2_clickHandler",
      "click .menu-logout": "logout_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "settings_clickHandler", "logout_clickHandler", "importBeta2_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["menuView"]({}));
      return this;
    },
    settings_clickHandler: function(event) {
      this.dismiss();
    },
    logout_clickHandler: function(event) {
      event.preventDefault();
      window.app.loginView.disable();
      this.dismiss();
      if (window.app.settings && window.app.settings.username) {
        delete window.app.settings.username;
        window.localStorage.setItem("settings", JSON.stringify(window.app.settings));
      }
      // Throw up the login screen
      window.app.loginView.show();
      window.setTimeout(function() {
        delete window.app.session;
        window.app.navigator.popAll(window.app.noEffect);
        window.app.mainView.close();
      },100);
      window.setTimeout(function() {
        window.app.loginView.enable();
      },350);
    },
    importBeta2_clickHandler: function(event) {
      event.preventDefault();
      var _this = this;
      this.dismiss();
      $(".blocker").show();
      window.app.session.load("_encryptrIndex", function(err, indexContainer) {
        window.app.session.load("entries", function(err, container) {
          if (err) {
            $(".blocker").hide();
            window.app.dialogAlertView.show({
              title: "Import error",
              subtitle: err
            }, function(){});
            return err;
          }
          var x = {};
          _.each(container.keys, function(value, key) {
            var ts = Date.now();
            value.id = undefined;
            x["model-"+ts] = new window.app.EntryModel(value);
            x["model-"+ts].save(null, { success: function(model){
              indexContainer.keys[model.id] = {
                id: model.id,
              label: value.label,
              type: value.type
              };
              if (x.length == container.keys.length) {
                indexContainer.save(function(err){});
                if (err) {
                  $(".blocker").hide();
                  window.app.dialogAlertView.show({
                    title: "Import error",
                    subtitle: err
                  }, function(){});
                } else {
                  window.app.session.deleteContainer("entries", function(err) {
                    window.app.dialogAlertView.show({
                      title: "Warning",
                      subtitle: "Logging out to complete the import"
                    }, function(){
                      _this.logout_clickHandler(event);
                    });
                  });
                }
                window.app.navigator.activeView.collection.fetch({
                  success: function() {
                    $(".blocker").hide();
                  }, error: function() {
                    $(".blocker").hide();
                  }
                });
              }
            }});
          });
        });
      });
    },
    about_clickHandler: function(event) {
      this.dismiss();
      window.app.dialogAlertView.show({
        title: "About Encryptr",
        subtitle: "Encryptr " + window.app.version + "<br>" +
          "encryptr.crypton.io <br><br>" +
          "Crypton " + window.crypton.version + "<br>" +
          "crypton.io"
      }, function() {});
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "-webkit-transform":"scale3d(0.8,0.8,0.8) translate3d(-10%,-10%,0)",
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

  Encryptr.prototype.MenuView = MenuView;

})(this, this.console, this.Encryptr);
