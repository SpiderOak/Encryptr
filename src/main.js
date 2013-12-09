var Encryptr = (function (window, console, undefined) {
  "use strict";
  console = console || {};
  console.log = console.log || function() {};

  
 
  var Encryptr = function () {
  this.online = true; // assume a hopeful default
  };
 
  Encryptr.prototype.init = function() {
    window.document.addEventListener("deviceready", this.onDeviceReady, false);
    window.document.addEventListener("resume", this.onResume, false);
    window.document.addEventListener("pause", this.onPause, false);
    window.document.addEventListener("offline", this.setOffline, false);
    window.document.addEventListener("online", this.setOnline, false);
  };
 
  Encryptr.prototype.onDeviceReady = function(event) {
    if (window.device.platform === "iOS" && parseFloat(window.device.version) >= 7.0) {
      window.document.querySelectorAll(".app")[0].style.top = "20px"; // status bar hax
    }
  };
 
  Encryptr.prototype.setOffline = function(event) {
    this.online = false;
  };
 
  Encryptr.prototype.setOnline = function(event) {
    this.online = true;
  };
 
  Encryptr.prototype.onResume = function(event) {
    // ...
  };
 
  Encryptr.prototype.onPause = function(event) {
    // ...
  };
 
  Encryptr.prototype.onBackButton = function(event) {
    navigator.app.exitApp();
  };
 
  Encryptr.prototype.onMenuButton = function(event) {
    // ...
  };
 
  return Encryptr;
 
})(window, window.console);