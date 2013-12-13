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
      if (options.error) options.error("No available session");
      return;
    }
    if (!options.container) {
      debug("ERROR: No container specified");
      if (options.error) options.error("No container specified");
      return;
    }
    var container = options.container;
    debug(method);
    switch (method) {
      case "read":
        if (model.isNew && model.isNew()) {
          if (options.success) options.success(model.toJSON());
          return;
        }
        if (!model.isNew) {
          debug("COLLECTION, WHAT NOW?!");
          return;
        }
        window.app.session.load(container, function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            debug("ERROR: " + err);
            if (options.error) options.error(err);
            return;
          }
          entries.get(model[model.idAttribute], function(err, entry) {
            if (options.success) options.success(entry);
          });
        });
        break;
      case "create":
        // @TODO: get rid of hardcoded "window.app" session container var
        //   ..think of a better way to store the session, maybe Backbone.session?
        window.app.session.load(container, function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            debug("ERROR: " + err);
            if (options.error) options.error(err);
            return;
          }
          var modelId = guid();
          entries.add(modelId, function(err) {
            if (err) {
              // @TODO: Add a better error object to return
              debug("ERROR: " + err);
              if (options.error)  options.error(err);
              return;
            }
            entries.get(modelId, function(err, entry) {
              if (err) {
                // @TODO: Add a better error object to return
                debug("ERROR: " + err);
                if (options.error)  options.error(err);
                return;
              }
              var modelData = model.toJSON();
              modelData[model.idAttribute] = modelData[model.idAttribute] || modelId;
              for(var data in modelData) {
                if (modelData.hasOwnProperty(data)) {
                  entry[data] = modelData[data];
                }
              }
              // entry.attributes = modelData;
              
              entries.save(function(err) {
                if (err) {
                  // @TODO: Add a better error object to return
                  debug("ERROR: " + err);
                  if (options.error)  options.error(err);
                  return;
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
            // @TODO: Add a better error object to return
            debug("ERROR: " + err);
            if (options.error)  options.error(err);
            return;
          }
          entries.get(model[model.idAttribute], function(err, entry) {
            if (err) {
              if (err === "Key does not exist") {
                Backbone.sync("create", model, options);
                return;
              }
              // @TODO: Add a better error object to return
              debug("ERROR: " + err);
              if (options.error)  options.error(err);
              return;
            }
            // entry.attributes = model.attributes;

            for (var attribute in model.attributes) {
              if (attribute === model.idAttribute) continue;
              if (model.attributes.hasOwnProperty(attribute)) {
                debug(attribute);
                entry[attribute] = model.attributes[attribute];
              }
            }
            entries.save(function(err) {
              if (err) {
                // @TODO: Add a better error object to return
                debug("ERROR: " + err);
                if (options.error)  options.error(err);
                return;
              }
              // ???
              if (options.success) options.success(entry);
            });
          });
        });
        break;
      case "delete":
        window.app.session.load(container, function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            debug("ERROR: " + err);
            if (options.error)  options.error(err);
            return;
          }
          delete entries.keys[model[model.idAttribute]];
          if (model.isNew()) {
            if (options.success) options.success(false);
            return;
          }
          entries.save(function(err) {
            if (err) {
              // @TODO: Add a better error object to return
              debug("ERROR: " + err);
              if (options.error)  options.error(err);
              return;
            }
            if (options.success) options.success(true);
          });
        });
        break;
    }
  };

})(this, this.console);