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
      "click .clearit": "clearSearch",
      "input input.search": "search",
      "submit form.entrySearch": "noop"
    },
    initialize: function() {
      _.bindAll(this, "render", "addAll", "addOne", "viewActivate", "search",
        "clearSearch", "viewDeactivate");
      this.collection.bind("reset", this.addAll, this);
      this.collection.bind("add", this.addOne, this);
      this.collection.bind("remove", this.addAll, this);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);

      this.subViews = [];
      this.hasItems = false;
      this.filterTimeout = undefined;
      this.clearSearchOnActive = false;
    },
    render: function() {
      this.$el.html(window.tmpl["entriesView"]({}));
      $(".clearit").addClass("hidden");
      return this;
    },
    addAll: function (collection) {
      var _this = this;
      collection = collection || this.collection;
      if (!window.app.mainView && !window.app.mainView.updatingLocalStorage) {
        this.$(".entriesViewLoading").removeClass("loadingEntries");
      }
      if (this.collection.models.length === 0) {
        window.setTimeout(function() {
          _this.$(".emptyFilteredEntries").hide();
          _this.$(".emptyEntries").show();
          _this.$(".entrySearch").hide();
        }, 300);
      } else {
        _this.$(".emptyFilteredEntries").hide();
        _this.$(".emptyEntries").hide();
        _this.$(".entrySearch").show();
      }
      this.$(".entries").html("");
      this.collection.each(this.addOne);
      this.search(this.filterText);
    },
    addOne: function(model) {
      var _this = this;
      this.$(".emptyEntries").hide();
      this.$(".emptyEntries").hide();
      this.$(".entrySearch").show();
      if (!window.app.mainView && !window.app.mainView.updatingLocalStorage) {
        this.$(".entriesViewLoading").removeClass("loadingEntries");
      }
      if (this.collection.models.length === 0) {
        window.setTimeout(function() {
          _this.$(".emptyEntries").show();
          _this.$(".entrySearch").hide();
        }, 300);
      } else {
        _this.$(".emptyEntries").hide();
        _this.$(".entrySearch").show();
      }
      var view = new Encryptr.prototype.EntriesListItemView({
        model: model
      });
      this.$(".entries").append(view.render().el);
      this.subViews.push(view);
    },
    noop: function(event) {
      event.preventDefault();
      return false;
    },
    search: function() {
      if (this.$("input.search").val()) {
        $(".clearit").removeClass("hidden");
      } else {
        $(".clearit").addClass("hidden");
      }
      var hasResults = false;
      if (this.collection.models.length === 0) {
        this.$("input.search").removeClass("error");
        return;
      }
      var filterEntries = function() {
        var filterText = this.$("input.search").val();
        this.filterText = filterText;
        this.$("input.search").removeClass("error");
        this.$(".emptyFilteredEntries").hide();
        this.$(".entries .entry").each(function(index, entry) {
          var $entry = $(entry);
          $entry.show();
          var label = $entry.find(".entry-label").text().toLowerCase();
          if (label.indexOf(filterText.toLowerCase()) === -1) {
            $entry.hide();
          } else {
            hasResults = true;
          }
        });
      }.bind(this);
      _.debounce(filterEntries(), 100);
      if (!hasResults) {
        this.$("input.search").addClass("error");
        this.$(".emptyFilteredEntries").show();
      }
    },
    clearSearch: function(event) {
      if (event) event.preventDefault();
      this.$("input.search").val("");
      this.search("");
    },
    viewActivate: function(event) {
      $('.subviews').scrollTop(0);
      if (this.filterTimeout) window.clearInterval(this.filterTimeout);
      if (this.clearSearchOnActive) this.clearSearch();
      this.clearSearchOnActive = false;
      var _this = this;
      window.app.mainView.backButtonDisplay(false);
      window.app.mainView.setTitle("Encryptr");
      $(".nav .add-btn.right").removeClass("hidden");
      $(".fab").removeClass("hidden");
      $(".fab").removeClass("shrunken");
      if ($.os.nodeWebkit) {
        _this.$("input.search").focus();
      }
      return this.getEntries().then(function(entries) {
        var promise = $.Deferred();
          if (entries.length === 0) {
            window.app.session.getContainer('_encryptrIndex', function(err, container) {
              _this.addAll();
              return promise.resolve();
            });
            return promise;
          }
          var indexJSON = JSON.stringify(entries.toJSON());
          if (window.app.accountModel.get("passphrase")) {
            var encryptedIndexJSON = window.sjcl.encrypt(
              window.app.accountModel.get("passphrase"), indexJSON,
              window.crypton.cipherOptions
            );
            var username = window.app.accountModel.get("username");
            var hashArray = window.sjcl.hash.sha256.hash(username);
            var hash = window.sjcl.codec.hex.fromBits(hashArray);
            window.localStorage.setItem("encryptr-" + hash + "-index",
              encryptedIndexJSON);
          }
      }, function(err) {
        if (!window.crypton.online){
          return _this.viewActivate(event);
        }
        window.app.session.create("_encryptrIndex", function(err, container) {
          if (err) {
            // OK. This is a bit more serious...
            window.app.dialogAlertView.show({
              title: "Error: Contact Support",
              subtitle: err
            }, function() {
              console.log("could not even recreate the container...");
            });
            return;
          }
          // the container should exist now...
          _this.viewActivate(event);
        });
      }).then(function() {
        if ($.os.ios || $.os.android || $.os.bb10 || $.os.nodeWebkit) {
          if (window.app.mainView && !window.app.mainView.updatingLocalStorage) {
            $(".entriesViewLoading").removeClass("loadingEntries");
          }
          window.app.mainView.updateLocalStorage();
          setInterval(window.app.mainView.updateLocalStorage.bind(window.app.mainView), 60*1000);
        }
      });
    },
    reloadIndex: function(){
      var self = this;
      var promise = $.Deferred();
      if (window.app.session && window.app.session.containers) {
        window.app.session.containers = [];
        if (window.app.entriesCollection) {
          window.app.entriesCollection.fetch({
            success: promise.resolve,
            error: promise.reject
          });
        }
      } else {
        promise.resolve(null);
      }
      return promise;
    },
    fixRecord: function(model, errorHandler, successHandler, options) {
      try {
        return model.destroy({
          success: function(model, response) {
            window.app.session.load("_encryptrIndex", function(err, container) {
              delete container.keys[model.id];
              container.save(function(err) {
                window.app.entriesCollection.fetch({
                  success: function(){
                    window.setTimeout(function(){
                      window.app.session.load("entries", function(){});
                      successHandler(null);
                    }, 100);
                  }
                });
              });
            });
          },
          error: function(err){errorHandler(err, options);}
        });
      } catch (err){
        errorHandler(err);
      }
    },
    getCollection: function(){
      var promise = $.Deferred();
      var username = window.app.accountModel.get("username");
      var hashArray = window.sjcl.hash.sha256.hash(username);
      var hash = window.sjcl.codec.hex.fromBits(hashArray);
      var encryptedIndexJSON = window.localStorage.getItem("encryptr-" + hash + "-index");
      if (encryptedIndexJSON && window.app.accountModel.get("passphrase")) {
        try {
          var decryptedIndexJson =
            window.sjcl.decrypt(window.app.accountModel.get("passphrase"),
                                encryptedIndexJSON, window.crypton.cipherOptions);
          promise.resolve(JSON.parse(decryptedIndexJson));
        } catch (ex) {
          window.app.toastView.show("Local cache invalid<br/>Loading from server");
          console.log(ex);
          promise.reject(ex);
        }
      } else {
        promise.resolve(null);
      }
      return promise;
    },
    getEntries: function(){
      var self = this;
      return this.getCollection().then(function success(collection){
        var promise = $.Deferred();
        if (collection) {
          self.collection.set(collection);
          self.$(".entriesViewLoading").text("syncing entries...");
          self.$(".entriesViewLoading").addClass("loadingEntries");
        }
        if (window.app.mainView && window.app.mainView.updatingLocalStorage) {
          $(".entriesViewLoading").text("Fetching data...");
          $(".entriesViewLoading").addClass("loadingEntries");
        }
        self.collection.fetch({
          container: "_encryptrIndex",
          success: promise.resolve,
          error: promise.reject
        });
        return promise;
      });
    },
    viewDeactivate: function(event) {
      var _this = this;
      $(".fab").addClass("hidden");
      _this.filterTimeout = window.setInterval(function() {
        _this.clearSearchOnActive = true;
        window.clearInterval(_this.filterTimeout);
      }, 5000);
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
      if (!$(".menu").hasClass("dismissed") ||
            !$(".addMenu").hasClass("dismissed")) {
        return;
      }
      $(".fab").addClass("shrunken");
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
