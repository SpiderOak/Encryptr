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

  /** NO LONGER NEEDED
  if (! navigator.notification.alert) {
    navigator.notification.alert =
        function (message, alertCallback, title, buttonName) {
          window.alert(message);
          if (alertCallback) {
            alertCallback();
          }
        };
  }

  if (! navigator.notification.confirm) {
    navigator.notification.confirm =
        function (message, confirmCallback, title, buttonLabels){
          var isConfirmed = window.confirm(message);
          if (confirmCallback)
          {
            confirmCallback((isConfirmed) ? 1 : 2);
          }
        };
  }
  */

  // Simulate onDeviceReady
  window.setTimeout(function(){
    var e = window.document.createEvent('Event');
    e.initEvent("deviceready", true, true);
    window.document.dispatchEvent(e);
  },300);

}
