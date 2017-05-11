(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var MainView = Backbone.View.extend({
    el: "#main",
    events: {
      "click .menu-btn": "menuButton_clickHandler",
      "click .export-btn": "exportButton_clickHandler",
      "click .share-btn": "shareButton_clickHandler",
      "click .copy-btn": "copyButton_clickHandler",
      "click .back-btn": "backButton_clickHandler",
      "click .edit-btn": "editButton_clickHandler",
      "click .save-btn": "saveButton_clickHandler",
      "click .delete-btn": "deleteButton_clickHandler",
      "click .add-btn": "addButton_clickHandler",
      "click .nav": "menuClose_clickHandler",
      "click .subviews": "menuClose_clickHandler"
    },
    initialize: function(options) {
      _.bindAll(this,
          "menuButton_clickHandler",
          "exportButton_clickHandler",
          "shareButton_clickHandler",
          "copyButton_clickHandler",
          "backButton_clickHandler",
          "addButton_clickHandler",
          "saveButton_clickHandler",
          "editButton_clickHandler",
          "deleteButton_clickHandler",
          "backButtonDisplay"
      );
      this.menuView = new Encryptr.prototype.MenuView().render();
      this.menuView.dismiss();
      this.addMenuView = new Encryptr.prototype.AddMenuView().render();
      this.addMenuView.dismiss();
      if (!$(".menu").length) this.$el.append(this.menuView.el);
      if (!$(".addMenu").length) this.$el.append(this.addMenuView.el);
      if ($.os.ios || $.os.android || $.os.bb10) {
        $('.nav .share-btn').removeClass('hidden');
        $('.nav .copy-btn').removeClass('hidden');
      } else {
        $('.nav .export-btn').removeClass('hidden');
      }
    },
    render: function() {
      this.$(".nav").html(
        window.tmpl["navView"]({})
      );
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
      if ($.os.nodeWebkit) {
        $('.fab').css({visibility: "hidden"});
      } else {
        $('.nav .add-btn.right').addClass('shrunken');
        $('.fab.add-btn').on('click', this.addButton_clickHandler);
      }
      return this;
    },
    menuButton_clickHandler: function(event) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      $('.nav .menu-btn').addClass('hidden');
      if ($.os.ios || $.os.android || $.os.bb10) {
        $('.nav .share-btn').addClass('hidden');
        $('.nav .copy-btn').addClass('hidden');
      } else {
        $('.nav .export-btn').addClass('hidden');
      }
      $(".fab").addClass("shrunken");
      window.app.navigator.pushView(window.app.SettingsView, {},
        window.app.defaultEffect);
    },
    addFieldFromEntry: function(entry, fields){
      entry.items.forEach(function(item) {
        var field = item.key;
        if (fields.indexOf(field) === -1) {
          fields.push(field);
        }
      });
    },
    getCsvFields: function(entries) {
      var fields = ['Entry Type', 'Label'];
      for (var index in entries){
        var entry = entries[index];
        this.addFieldFromEntry(entry, fields);
      }
      return fields;
    },
    addDataFromEntry: function(entry, fields){
      var entry_data = {};
      entry.items.forEach(function(item) {
        var field = item.key;
        entry_data[field] = item.value;
      });
      entry_data['Entry Type'] = entry.type;
      entry_data['Label'] = entry.label;
      return entry_data;
    },
    getCsvData: function(entries, fields) {
      var data = [];
      for (var index in entries){
        var entry = entries[index];
        data.push(this.addDataFromEntry(entry, fields));
      }
      return data;
    },
    writeCordovaFile: function(fileName, data, options) {
      data = JSON.stringify(data, null, '\t');
      var success = options.success || function() {};
      window.resolveLocalFileSystemURL(cordova.file.cacheDirectory, function (directoryEntry) {
          directoryEntry.getFile(fileName, { create: true }, function (fileEntry) {
              fileEntry.createWriter(function (fileWriter) {
                  fileWriter.onwriteend = function (e) {
                      console.log('Write of file "' + fileName + '"" completed.');
                  };
                  fileWriter.onerror = function (e) {
                      console.log('Write failed: ' + e.toString());
                  };
                  var blob = new Blob([data], { type: 'text/plain' });
                  fileWriter.write(blob);
                  success(fileEntry.fullPath);
              }, console.log);
          }, console.log);
      }, console.log);
    },
    saveCsv: function(csv){
      if ($.os.ios || $.os.android || $.os.bb10) {
        this.writeCordovaFile('export.csv', csv, {success: function(filePath) {
          var options = {
            message: 'Encryptr csv with entries data',
            files: [filePath],
            subject: 'Encryptr data'
          };
          window.plugins.socialsharing.shareWithOptions(options);
        }});
      } else {

      }
    },
    generateCsvFromEntries: function(entries) {
      var fields = this.getCsvFields(entries);
      var data = this.getCsvData(entries, fields);
      var csv = json2csv({'data': data, 'fields': fields});
      this.saveCsv(csv);
    },
    getEntries: function(options) {
      var success = options.success || console.log;
      var username = window.app.accountModel.get("username");
      var hashArray = window.sjcl.hash.sha256.hash(username);
      var hash = window.sjcl.codec.hex.fromBits(hashArray);
      var encryptedIndexJSON = window.localStorage.getItem("encryptr-" + hash + "-index");
      if (encryptedIndexJSON && window.app.accountModel.get("passphrase")) {
        try {
          var decryptedIndexJson =
            window.sjcl.decrypt(window.app.accountModel.get("passphrase"),
                                encryptedIndexJSON, window.crypton.cipherOptions);
          var promises = JSON.parse(decryptedIndexJson).map(function(entry) {
            var entry_model = new window.app.EntryModel(entry);
            var promise = $.Deferred();
            entry_model.fetch({success: function(_, resp){
              promise.resolve(resp);
            }});
            return promise;
          });
          $.when.apply($, promises).then(success);
        } catch (ex) {
          window.app.toastView.show("Local cache invalid<br/>Loading from server");
          console.log(ex);
          return ex;
        }
      }
    },
    exportButton_clickHandler: function(event) {
      var self = this;
      event.stopPropagation();
      event.stopImmediatePropagation();
      $(".entriesViewLoading").text("loading entries...");
      $(".entriesViewLoading").addClass("loadingEntries");
      this.getEntries({success: function(){
        var entries = arguments;
        $(".entriesViewLoading").removeClass("loadingEntries");
        self.generateCsvFromEntries(entries);
      }});
    shareButton_clickHandler: function(event) {
      var self = this;
      event.stopPropagation();
      event.stopImmediatePropagation();
      return this.getCsv().then(function (csv) {
        return self.writeCordovaFile('export.csv', csv);
      }).then(function(filePath) {
        var options = {
          message: 'Encryptr csv with entries data',
          files: [cordova.file.cacheDirectory + filePath],
          subject: 'Encryptr data'
        };
        window.plugins.socialsharing.shareWithOptions(options);
      });
    },
    copyButton_clickHandler: function(event) {
      var self = this;
      event.stopPropagation();
      event.stopImmediatePropagation();
      return this.getCsv().then(function (csv){
        cordova.plugins.clipboard.copy(csv);
        window.app.toastView.show("The entries were successfully copied in clipboard");
      });
    },
    backButton_clickHandler: function(event) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      var _this = this;
      if (window.app.navigator.activeView.confirmBackNav) {
        window.app.dialogConfirmView.show(window.app.navigator.activeView.confirmBackNav,
            function(event) {
              if (event.type === "dialogAccept") {
                _this.backButtonDisplay(false);
                if (window.app.navigator.viewsStack.length > 1) {
                  window.app.navigator.popView(window.app.defaultPopEffect);
                }
                window.app.navigator.activeView.confirmBackNav.callback();
              }
            });
      } else {
        //_this.backButtonDisplay(false);
        this.$(".back-btn").addClass("hidden");
        if (window.app.navigator.viewsStack.length > 1) {
          window.app.navigator.popView(window.app.defaultPopEffect);
        }
      }
    },
    addButton_clickHandler: function(event) {
      event.preventDefault();
      this.addMenuView.toggle();
    },
    editButton_clickHandler: function(event) {
      this.trigger("editentry");
    },
    saveButton_clickHandler: function(event) {
      this.trigger("saveentry");
    },
    deleteButton_clickHandler: function(event) {
      this.trigger("deleteentry");
    },
    setTitle: function(title) {
      if (title === "Encryptr") {
        this.$('.nav .title .text-gradient')
          .html('<img src="img/LogoColoured.svg" style="height: 32px; padding: 12px 0;">');
      } else {
        this.$(".nav .title .text-gradient").text(title);
      }
    },
    backButtonDisplay: function(show) {
      if (show) {
        this.$(".back-btn").removeClass("hidden");
        this.$(".menu-btn").addClass("hidden");
        if ($.os.ios || $.os.android || $.os.bb10) {
          $('.nav .share-btn').addClass('hidden');
          $('.nav .copy-btn').addClass('hidden');
        } else {
          $('.nav .export-btn').addClass('hidden');
        }
        return;
      }
      this.$(".back-btn").addClass("hidden");
      this.$(".menu-btn").removeClass("hidden");
      if ($.os.ios || $.os.android || $.os.bb10) {
        $('.nav .share-btn').removeClass('hidden');
        $('.nav .copy-btn').removeClass('hidden');
      } else {
        $('.nav .export-btn').removeClass('hidden');
      }
    },
    cancelDialogButton_clickHandler: function(event) {
      // ...
    },
    acceptDialogButton_clickHandler: function(event) {
      // ...
    },
    menuClose_clickHandler: function(event) {
      if (!this.menuView.$el.hasClass("dismissed") &&
          !$(event.target).hasClass("fa-ellipsis-v") &&
          !$(event.target).hasClass("menu-btn")) {
        this.menuView.dismiss();
      }
      if (!this.addMenuView.$el.hasClass("dismissed") &&
          !$(event.target).hasClass("fa-plus") &&
          !$(event.target).hasClass("add-btn")) {
        this.addMenuView.dismiss();
      }
    },
    close: function() {
      this.menuView.close();
      this.addMenuView.close();
      $('.add-btn').off('click', this.addButton_clickHandler);
    }
  });

  Encryptr.prototype.MainView = MainView;

})(this, this.console, this.Encryptr);
