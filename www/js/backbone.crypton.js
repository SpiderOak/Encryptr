/*! Backbone.crypton - v0.1.0 - 2013-12-11

 * Copyright (c) 2013 tommy-carlos williams (devgeeks);
 * License: Apache2 (http://www.apache.org/licenses/LICENSE-2.0)
 */
 (function(window, console, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var debug     = function(msg) { console.log(msg); };
  var Backbone  = window.Backbone,
      _         = window._,
      $         = window.Zepto,
      crypton   = window.crypton;

  function S4(){
    return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
  }

  function guid() {
    return (S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4());
  }

  Backbone.sync = function(method, model, options) {
    var _this = this;
    var session = window.app.accountModel.get("session");
    var errorHandler = function (err, options) {
      debug("ERROR: " + err);
      return options.error && options.error(err);
    };
    var successHandler = function(resp) {
      return options.success && options.success(resp);
    };
    options = options || {};
    if (!session) {
      debug("ERROR: No available session");
      return options.error && options.error("No available session");
    }

    debug(method);
    switch (method) {
      case "read":
        if (model.isNew && model.isNew()) {
          return successHandler(model.toJSON());
        }
        if (!model.isNew) {
          debug("Collection: This should not happen.");
          // Should we be calling model.collection.sync?
          return;
        }
        session.load(model.id, function(err, container) {
          if (err) {
            console.error(err);
            return errorHandler(err, options);
          }
          return successHandler(container.keys);
        });
        break;
      case "create":
        var modelId = guid();
        session.create(modelId, function(err) {
          if (err) {
            console.error(err);
            return errorHandler(err, options); // throw an error if it exists, etc
          }
          session.load(modelId, function(err, container) {
            if (err) {
              console.error(err);
              return errorHandler(err, options); // throw an error if it exists, etc
            }
            var modelData = model.toJSON();
            modelData.id = modelId;
            container.keys = _.extend(container.keys, modelData);
            container.save(function(err) {
              if (err) {
                console.error(err);
                return errorHandler(err, options);
              }
              model[model.idAttribute] = modelId;
              return successHandler(modelData);
            });
          });
        });
        break;
      case "update":
        // ...
        break;
      case "delete":
        // ...
        break;
    }
  };

})(this, this.console);
