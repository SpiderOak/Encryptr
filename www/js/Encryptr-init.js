(function() {
  // Replace <body onouchstart="">
  document.addEventListener('touchstart', document.body, function() {});
  // back the version up then re-add it
  var version = window.app.version;
  // replace the window.app from Encryptr.js with a real one
  window.app = new Encryptr();
  window.app.version = version;
  window.app.init();
  window.app.navigator = new window.BackStack.StackNavigator({el:'#subviews'});
})();
