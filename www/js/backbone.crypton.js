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
    options = options || {};
    if (!window.app.session) {
      debug("ERROR: No available session");
      return options.error && options.error("No available session");
    }
    var container = model.container || options.container;
    if (!container) {
      debug("ERROR: No container specified");
      return options.error && options.error("No container specified");
    }
    
    debug(method);
    switch (method) {
      case "read":
        if (model.isNew && model.isNew()) {
          return options.success && options.success(model.toJSON());
        }
        if (!model.isNew) {
          debug("COLLECTION, WHAT NOW?!");
          return;
        }
        window.app.session.load(container, function(err, entries) {
          if (err) {
            debug("ERROR: " + err);
            return options.error && options.error(err);
          }
          entries.get(model[model.idAttribute], function(err, entry) {
            if (options.success) options.success(entry);
          });
        });
        break;
      case "create":
        window.app.session.load(container, function(err, entries) {
          if (err) {
            debug("ERROR: " + err);
            return options.error && options.error(err);
          }
          var modelId = guid();
          entries.add(modelId, function(err) {
            if (err) {
              debug("ERROR: " + err);
              return options.error && options.error(err);
            }
            entries.get(modelId, function(err, entry) {
              if (err) {
                debug("ERROR: " + err);
                return options.error && options.error(err);
              }
              var modelData = model.toJSON();
              modelData[model.idAttribute] = modelData[model.idAttribute] || modelId;
              for(var data in modelData) {
                if (modelData.hasOwnProperty(data)) {
                  entry[data] = modelData[data];
                }
              }
              
              entries.save(function(err) {
                if (err) {
                  debug("ERROR: " + err);
                  return options.error && options.error(err);
                }
                model[model.idAttribute] = modelId;
                if (options.success) options.success(entry);
              });
            });
          });
        });
        break;
      case "update":
        window.app.session.load(container, function(err, entries) {
          if (err) {
            debug("ERROR: " + err);
            return options.error && options.error(err);
          }
          entries.get(model[model.idAttribute], function(err, entry) {
            if (err) {
              if (err === "Key does not exist") {
                Backbone.sync("create", model, options);
                return;
              }
              debug("ERROR: " + err);
              return options.error && options.error(err);
            }

            for (var attribute in model.attributes) {
              if (attribute === model.idAttribute) continue;
              if (model.attributes.hasOwnProperty(attribute)) {
                entry[attribute] = model.attributes[attribute];
              }
            }
            entries.save(function(err) {
              if (err) {
                debug("ERROR: " + err);
                return options.error && options.error(err);
              }
              return options.success && options.success(entry);
            });
          });
        });
        break;
      case "delete":
        window.app.session.load(container, function(err, entries) {
          if (err) {
            debug("ERROR: " + err);
            return options.error && options.error(err);
          }
          delete entries.keys[model[model.idAttribute]];
          if (model.isNew()) {
            return options.success && options.success(false);
          }
          entries.save(function(err) {
            if (err) {
              debug("ERROR: " + err);
              return options.error && options.error(err);
            }
            return options.success && options.success(true);
          });
        });
        break;
    }
  };

})(this, this.console);
