(function(window, console, app, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
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
    options = options || {};
    if (!window.app.session) {
      options.error("No available session");
      return;
    }
    console.log(method);
    switch (method) {
      case "read":
        if (model.isNew && model.isNew()) {
          options.success(model.toJSON());
          return;
        }
        if (!model.isNew) {
          console.log("COLLECTION, WHAT NOW?!");
          return;
        }
        window.app.session.load("Entries", function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            options.error(err);
            return;
          }
          entries.get(model.id, function(err, entry) {
            options.success(entry.attributes);
          });
        });
        break;
      case "create":
        // @TODO: get rid of hardcoded "window.app" session container var
        //        ..think of a better way to store the session, maybe Backbone.session?
        // @TODO: get rid of hardcoded "Entries" container name
        window.app.session.load("Entries", function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            options.error(err);
            return;
          }
          var modelId = guid();
          entries.add(modelId, function(err) {
            if (err) {
              // @TODO: Add a better error object to return
              options.error(err);
              return;
            }
            entries.get(modelId, function(err, entry) {
              if (err) {
                // @TODO: Add a better error object to return
                options.error(err);
                return;
              }
              var modelData = model.toJSON();
              modelData.id = modelId;
              entry.attributes = modelData;
              
              entries.save(function(err) {
                if (err) {
                  // @TODO: Add a better error object to return
                  options.error(err);
                  return;
                }
                model.id = modelId;
                options.success(model);
              });
            });
          });
        });
        break;
      case "update":
        window.app.session.load("Entries", function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            options.error(err);
            return;
          }
          entries.get(model.id, function(err, entry) {
            entry.attributes = model.attributes;
            entries.save(function(err) {
              if (err) {
                // @TODO: Add a better error object to return
                options.error(err);
                return;
              }
              options.success(model.attributes);
            });
          });
        });
        break;
      case "delete":
        window.app.session.load("Entries", function(err, entries) {
          if (err) {
            // @TODO: Add a better error object to return
            options.error(err);
            return;
          }
          delete entries.keys[model.get(model.idAttribute)];
          if (model.isNew()) {
            options.success(false);
            return;
          }
          entries.save(function(err) {
            if (err) {
              // @TODO: Add a better error object to return
              options.error(err);
              return;
            }
            options.success(true);
          });
        });
        break;
    }
  };

})(this, this.console, this.app);