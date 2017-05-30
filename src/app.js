var Encryptr = (function (window, console, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
      _         = window._,
      $         = window.Zepto;

  var Encryptr = function () {
    this.online = true; // assume a hopeful default
    this.offline_btns = [];
  };

  Encryptr.prototype.init = function() {
    window.document.addEventListener("deviceready", this.onDeviceReady, false);
    window.document.addEventListener("resume", this.onResume, false);
    window.document.addEventListener("pause", this.onPause, false);
    window.document.addEventListener("offline", this.setOffline, false);
    window.document.addEventListener("online", this.setOnline, false);
    document.addEventListener('dragover', function(e){
      e.preventDefault();
      e.stopPropagation();
    },  false);
    document.addEventListener('drop', function(e){
      e.preventDefault();
      e.stopPropagation();
    }, false);

    var settings = window.localStorage.getItem("settings") || "{}";
    window.app.settings = JSON.parse(settings);

    // Set the hostname for the Crypton server
    // window.crypton.host = "192.168.1.12";
    window.crypton.host = "encryptrstaging.crypton.io";
    window.crypton.port = 443;

    window.Offline.options = {
      // Should we check the connection status immediatly on page load.
      checkOnLoad: false,

      // Should we monitor AJAX requests to help decide if we have a connection.
      interceptRequests: true,

      // Should we automatically retest periodically when the connection is
      // down (set to false to disable).
      reconnect: {
        // How many seconds should we wait before rechecking.
        initialDelay: 3
      },

      // Should we store and attempt to remake requests which fail while the
      // connection is down.
      requests: true,

      // Should we show a snake game while the connection is down to keep
      // the user entertained?
      // It's not included in the normal build, you should bring in
      // js/snake.js in addition to offline.min.js.
      game: false,

      // What the xhr checks
      checks: {
        xhr: {
          url: ("https://" +
                window.crypton.host +
                (window.crypton.port ? (":" + window.crypton.port) : "") +
                "/")
        }
      }
    };
    window.Offline.on('up', this.setOnline.bind(this));
    window.Offline.on('confirmed-up', this.setOnline.bind(this));
    window.Offline.on('down', this.setOffline.bind(this));
    window.Offline.on('confirmed-down', this.setOffline.bind(this));

    var isNodeWebkit = (typeof process == "object");
    if (isNodeWebkit) $.os.nodeWebkit = true;
    // Render the login view (and bind its events)
    this.loginView = new this.LoginView().render();
    // Hax for Android 2.x not groking :active
    $(document).on("touchstart", "a", function(event) {
      var $this = $(this);
      $this.addClass("active");
    });
    $(document).on("touchend", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });
    $(document).on("touchcancel", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });
    $(document).on("touchmove", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });

    this.dialogConfirmView = new Encryptr.prototype.DialogConfirmView().render();
    this.dialogConfirmView.dismiss();
    $("#main").append(this.dialogConfirmView.el);
    this.dialogAlertView = new Encryptr.prototype.DialogAlertView().render();
    this.dialogAlertView.dismiss();
    $("#main").append(this.dialogAlertView.el);

    window.FastClick.attach(document.body);

    // Backstack effects
    Encryptr.prototype.noEffect = new window.BackStack.NoEffect();
    Encryptr.prototype.fadeEffect = new window.BackStack.FadeEffect();
    Encryptr.prototype.defaultEffect = new Encryptr.prototype.PopFadeEffect();
    Encryptr.prototype.defaultPopEffect = new Encryptr.prototype.PopFadeEffect({
      direction: "right"
    });
  };

  Encryptr.prototype.onDeviceReady = function(event) {
    // Useragent sniffin. Ew.
    if ($.os.ios && parseFloat(window.device.version) >= 7.0) {
      $(".app").css({"top":"20px"});
    }
    if (window.StatusBar && $.os.ios) {
      window.StatusBar.styleDefault();
      $("body").addClass("ios");
    }
    if (window.StatusBar && $.os.android) {
      window.StatusBar.backgroundColorByHexString("#C1235b");
    }
    window.document.addEventListener("backbutton",
                                     Encryptr.prototype.onBackButton, false);
    window.document.addEventListener("menubutton",
                                     Encryptr.prototype.onMenuButton, false);

    window.app.checkVersion();

    if (!$.os.nodeWebkit) {
      // overflow: auto !important; -webkit-overflow-scrolling: touch;
      $(".subviews").css({
        "overflow":"auto !important",
        "-webkit-overflow-scrolling":"touch"
      });
    }
    // Platform specific clipboard plugin / code
    if ($.os.ios || $.os.android) {
      Encryptr.prototype.copyToClipboard = window.cordova.plugins.clipboard.copy;
    } else if ($.os.bb10) {
      Encryptr.prototype.copyToClipboard = window.community.clipboard.setText;
    // How to *actually* detect node-webkit ?
    } else if ($.os.nodeWebkit && window.require ) {
      /* jshint node: true */
      var gui = require('nw.gui');
      var win = gui.Window.get();
      if (process.platform === "darwin") {
        var nativeMenuBar = new gui.Menu({ type: "menubar" });
        nativeMenuBar.createMacBuiltin("Encryptr");
        win.menu = nativeMenuBar;
      }
      var option = {
        key : "Ctrl+F",
        active : function() {
          if ($("input.search").length > 0) {
            $("input.search").focus();
          }
        },
        failed : function(msg) {
          // :(, fail to register the |key| or couldn't parse the |key|.
          console.log(msg);
        }
      };
      // Create a shortcut with |option|.
      var shortcut = new gui.Shortcut(option);
      gui.App.registerGlobalHotKey(shortcut);
      // ...but turn it off when not focused
      win.on("blur", function() {
        gui.App.unregisterGlobalHotKey(shortcut);
      });
      win.on("focus", function() {
        gui.App.registerGlobalHotKey(shortcut);
      });

      window.clipboard = gui.Clipboard.get();
      Encryptr.prototype.copyToClipboard = function(text) {
        window.clipboard.set(text, 'text');
      };
      /* jshint node: false */
    } else {
      // Fallback to empty browser polyfill
      Encryptr.prototype.copyToClipboard = function() {};
    }
  };

  Encryptr.prototype.loadOfflineData = function() {
    var self = this;
    if ($.os.ios || $.os.android || $.os.bb10) {
      return this.readOfflineDataCordova('encrypt.data').then(function(data){
        window.sessionStorage.setItem('crypton', data);
      }, function(err) {
        window.app.toastView.show("We are having trouble reading the data while offline, please connect to the internet");
        console.err(err);
      });
    } else if ($.os.nodeWebkit) {
      return this.readOfflineDataInDesktop('encrypt.data').then(function(data){
        window.sessionStorage.setItem('crypton', data);
      }, function(err) {
        window.app.toastView.show("We are having trouble reading the data while offline, please connect to the internet");
        console.err(err);
      });
    }
  };

  Encryptr.prototype.readCordovaFile = function(directory, fileName){
    var promise = $.Deferred();
    window.resolveLocalFileSystemURL(directory, function (directoryEntry) {
      directoryEntry.getFile(fileName, {}, function (fileEntry) {
        fileEntry.file(function (file) {
          var reader = new FileReader();
          reader.onloadend = function() {
          promise.resolve(this.result);
          };
          reader.readAsText(file);
        }, promise.reject);
      }, promise.reject);
    }, promise.reject);
    return promise;
  };

  Encryptr.prototype.readOfflineDataCordova = function(file){
    return this.readCordovaFile(cordova.file.dataDirectory, file);
  };

  Encryptr.prototype.readOfflineDataInDesktop = function(file){
    var nw = require('nw.gui');
    var fs = require('fs');
    var path = require('path');
    var promise = $.Deferred();
    var filePath = path.join(nw.App.dataPath, file);
    fs.readFile(filePath, 'utf8', function(err, data) {
      if (err) {
        return promise.reject(err);
      }
      promise.resolve(data);
    });
    return promise;
  };

  Encryptr.prototype.checkonline = function(btns_classes){
    var self = this;
    btns_classes.map(function(btn_class) {
      if (self.offline_btns.indexOf(btn_class) === -1){
        self.offline_btns.push(btn_class);
      }
    });
    var setStatus = (this.online) ? this.setOnline:this.setOffline;
    return setStatus.bind(this)();
  };

  Encryptr.prototype.setOffline = function(event) {
    this.online = false;
    window.online = false;
    window.crypton.online = false;
    this.offline_btns.forEach(function(btn_class) {
      $(btn_class).addClass('disabled-link disabled-btn');
    });
    if (window.sessionStorage.getItem('crypton') === null) {
      app.loadOfflineData();
    }
  };

  Encryptr.prototype.setOnline = function(event) {
    this.online = true;
    window.online = true;
    window.crypton.online = true;
    this.offline_btns.forEach(function(btn_class) {
      $(btn_class).removeClass('disabled-link disabled-btn');
    });
  };

  Encryptr.prototype.onResume = function(event) {
    // Logging out seems a bit overkill
    // For now, put a 10 minute timeout on it...
    var timeoutInMinutes =
      Math.floor(((Date.now() - window.app.lastPaused) / 1000) / 60);
    if (timeoutInMinutes >= 10) {
      window.clearInterval(window.app.logoutInterval);
      window.app.accountModel.logout(function() {
        window.app.loginView.disable();
        // Throw up the login screen
        window.app.loginView.show();
        window.setTimeout(function() {
          if (window.app.navigator.viewsStack.length > 0) {
            window.app.navigator.popAll(window.app.noEffect);
          }
          window.app.mainView.close();
        },100);
        window.setTimeout(function() {
          window.app.loginView.enable();
        },350);
        window.setTimeout(window.app.checkVersion,1000);
      });
    }
  };

  Encryptr.prototype.onPause = function(event) {
    window.app.lastPaused = Date.now();
  };

  Encryptr.prototype.onBackButton = function(event) {
    if ($(".dialogAlert").is(":visible")) {
      window.app.dialogAlertView.dismiss();
      return;
    }
    if ($(".dialogConfirm").is(":visible")) {
      window.app.dialogConfirmView.dismiss();
      return;
    }
    if ($(".menu").is(":visible")) {
      window.app.mainView.menuView.dismiss();
      return;
    }
    if ($(".addMenu").is(":visible")) {
      window.app.mainView.addMenuView.dismiss();
      return;
    }
    if ($(".back-btn").is(":visible")) {
      if (window.app.navigator.activeView.confirmBackNav) {
        window.app.dialogConfirmView.show(window.app.navigator.activeView.confirmBackNav,
            function(event) {
              if (event.type === "dialogAccept") {
                if (window.app.navigator.viewsStack.length > 1) {
                  window.app.mainView.backButtonDisplay(false);
                  window.app.navigator.popView(window.app.defaultPopEffect);
                }
                window.app.navigator.activeView.confirmBackNav.callback();
              }
            });
      } else {
        if (window.app.navigator.viewsStack.length > 1) {
          window.app.mainView.backButtonDisplay(false);
          window.app.navigator.popView(window.app.defaultPopEffect);
        }
      }
      return;
    }
    navigator.app.exitApp();
  };

  Encryptr.prototype.onMenuButton = function(event) {
    // ...
  };

  Encryptr.prototype.checkVersion = function(ignoreOptional) {
    var buster = Date.now();
    $.getJSON("https://encryptr.org/_latestVersion.json?v=" + buster, function(versionData) {
      var latestVersion = window.semver.gte(window.app.version, versionData.tag_name);
      if (!latestVersion) {
        if (ignoreOptional && versionData.priority === "optional") {
          return;
        }
        window.app.dialogConfirmView.show({
          title: "New version available",
          subtitle: "The new " + versionData.tag_name + " release is " +
              versionData.priority + ". Would you like to download it now?"
        },
        function(event) {
          if (event.type === "dialogAccept") {
            if ($.os.nodeWebkit) {
              window.require('nw.gui').Shell.openExternal(versionData.url);
              return false;
            }
            window.open(versionData.url, "_system");
          }
        });
      }
    });
  };

  Encryptr.prototype.randomString = function(length) {
    var charset = "!@#$%^*()_+{}:?|,[];./~ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "abcdefghijklmnopqrstuvwxyz0123456789";
    var i;
    var result = "";
    if(window.crypto && window.crypto.getRandomValues) {
      var values = new Uint32Array(length);
      window.crypto.getRandomValues(values);
      for(i = 0; i < length; i++) {
          result += charset[values[i] % charset.length];
      }
    }
    return result; // If you can't say something nice, don't say anything at all
  };

  return Encryptr;

})(this, this.console);
