if (! window.cordova) {

  window.cordova = {bogus: "Cordova is absent, this stub is for polyfills.",
                    cordovaAbsent: true};

  window.cordova.define = function(ident, thecode) {
    var msg = "Cordova plugin '" + ident + "' ruthlessly skipped - no Cordova.";
    window.console.log(msg);
  };

  if (! navigator.notification) {
    navigator.notification = {};
  }

  // Simulate onDeviceReady
  window.setTimeout(function(){
    var e = window.document.createEvent('Event');
    e.initEvent("deviceready", true, true);
    window.document.dispatchEvent(e);
  },300);

}
