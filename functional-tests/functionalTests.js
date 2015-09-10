/* global describe, before, beforeEach, after, it */
'use strict';

require("mocha-as-promised")();

var path = require('path');
var projectRoot = path.resolve(__dirname, '..');

require('colors');
var chai = require("chai");
var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
chai.should();

var wd = require('wd');
var wdQuery = require("wd-query");

// enables chai assertion chaining
chaiAsPromised.transferPromiseness = wd.transferPromiseness;

describe('Encryptr', function() {
  this.timeout(50000);
  var browser;
  var appURL;
  var $;

  var newusername = "user" + Date.now().toString();
  var newpassphrase = "shhh" + Date.now().toString();

  if (process.env.APPIUM === "android") {
    appURL = projectRoot + "/platforms/android/ant-build/Encryptr-debug.apk";
  }
  else {
    appURL = projectRoot + "/platforms/ios/build/emulator/Encryptr.app";
  }

  before(function() {
    browser = wd.promiseChainRemote("localhost", 4723);
    $ = wdQuery(browser);
    return browser
      .init({
        'app-package': (process.env.APPIUM === "android") ? 'org.devgeeks.encryptr' : undefined,
        'app-activity': (process.env.APPIUM === "android") ? '.Encryptr' : undefined,
        name: "Encryptr",
        platformName: (process.env.APPIUM === "android") ? "Android" : "iOS",
        platformVersion: '8.4',
        deviceName: (process.env.APPIUM === "android") ? 'Android VM' : 'iPhone 6',
        app: appURL,
        implicitWaitMs: 500
      })
      .contexts()
      .then(function(contexts) {
        console.log(contexts);
        return browser;
      })
      .setImplicitWaitTimeout(20000)
      .context((process.env.APPIUM === "android") ? 'WEBVIEW_org.devgeeks.encryptr' : 'WEBVIEW_1');
      // .setAsyncScriptTimeout(30000)
      //.windowHandles()
      //.then(function(handles) {
        //console.log(handles);
        //return (process.env.APPIUM === "android") ? browser.window(handles[1]) : browser.window(handles[0]);
      //});
  });

  after(function() {
    return browser.noop()
    .then(function() { return browser.quit(); }).done();
  });

  // using mocha-as-promised and chai-as-promised is the best way
  describe("Functional tests", function() {

    beforeEach(function() {
      // ...
    });

// Registration :: "user" + Date.now().toString()
    describe("Registration", function() {
      it("should have a 'Register for an account »' link", function() {
        return browser
          .waitForElementByCss(".signupButton")
          .then(function() {
            return browser.elementByCss(".signupButton");
          }).should.eventually.be.ok;
      });
      it("should have the correct text", function() {
          return browser.elementByCss(".signupButton")
          .then(function(el) {
            return el.text();
          }).should.eventually.equal("Register for an account »");
      });
      it("should be able to switch to the registration screen", function() {
        return browser
          .waitForElementByCss(".signupButton")
          .then(function() {
            return $(".signupButton").click();
          })
          .then(function() {
            return browser.sleep(200);
          })
          .then(function() {
            return browser.waitForElementByCss("input[name=newusername]");
          }).should.eventually.be.ok;
      });
      it("should be able to hide the passphrase", function() {
        return browser
          .waitForElementByCss("#show-passphrase")
          .then(function() {
            return browser.waitForElementByCss("label[for=show-passphrase]");
          })
          .then(function() {
            return $("label[for=show-passphrase]").click();
          })
          .then(function() {
            return wd.asserters.jsCondition("document.querySelector('#newpassphrase').type === 'password'");
          }).should.eventually.be.ok;
      });
      it("should be able to show the passphrase", function() {
        return browser
          .waitForElementByCss("#show-passphrase")
          .then(function() {
            return browser.waitForElementByCss("label[for=show-passphrase]");
          })
          .then(function() {
            return $("label[for=show-passphrase]").click();
          })
          .then(function() {
            return wd.asserters.jsCondition("document.querySelector('#newpassphrase').type === 'text'");
          }).should.eventually.be.ok;
      });
      it("should display an error when username or passphrase are empty", function() {
        return browser
          .waitForElementByCss(".button.signupButton")
          .then(function() {
            return $(".button.signupButton").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert:not(.dismissed)");
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert .dialog .title");
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("document.querySelector('.dialogAlert .dialog .subtitle').innerText === 'Must supply username and passphrase'"));
          }).should.eventually.be.ok;
      });
      it("should be able to dismiss the authentication error", function() {
        return browser.noop()
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert .buttons .button.dialog-accept-btn");
          })
          .then(function() {
            return $(".dialogAlert .buttons .button.dialog-accept-btn").click();
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("!!document.querySelector('.dialogAlert.dismissed')"));
          }).should.eventually.be.ok;
      });
      it("should be able to enter a new username", function() {
        return browser.noop()
          .then(function() {
            return $('input[name=newusername]').val(newusername);
          })
          .then(function() {
            return $('input[name=newusername]').val();
          }).should.eventually.equal(newusername);
      });
      it("should be able to enter a new passphrase", function() {
        return browser.noop()
          .then(function() {
            return $('input[name=newpassphrase]').val(newpassphrase);
          })
          .then(function() {
            return $('input[name=newpassphrase]').val();
          }).should.eventually.equal(newpassphrase);
      });
      it("should be able to register", function() {
        return browser
          .waitForElementByCss(".button.signupButton")
          .then(function() {
            return $(".button.signupButton").click();
          })
          .then(function() {
            return browser
              .waitForElementByCss(".login.dismissed");
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'"));
          })
          .then(function() {
            return $(".emptyEntries").text();
          })
          .then(function(text) {
            return text;
          }).should.eventually.equal("No entries yet\nAdd some now with the '+' above");
      });
    });
// Start over
    describe("Start over", function() {
      it("should have a menu button", function() {
        return browser
          .waitForElementByCss(".menu-btn")
          .then(function() {
            return $(".menu-btn");
          }).should.eventually.be.ok;
      });
      it("should be able to log out", function() {
        return browser
          .waitForElementByCss(".menu-btn")
          .then(function() {
            return $(".menu-btn").click();
          })
          .then(function() {
            return browser.sleep(120);
          })
          .then(function() {
            return browser.waitForElementByCss(".menu-logout");
          })
          .then(function() {
            return $(".menu-logout").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".login:not(.dismissed)");
          })
          .then(function() {
            return $(".login:not(.dismissed)");
          }).should.eventually.be.ok;
      });
    });
// Log back in
    describe("Log in", function() {
      it("should have a username field", function() {
        return browser.noop()
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("document.querySelectorAll('input[name=username]')[0].disabled == false"));
          })
          .then(function() {
            return browser.waitForElementByCss("input[name=username]");
          })
          .then(function() {
            return browser.elementByCss("input[name=username]");
          }).should.eventually.be.ok;
      });
      it("should have a placeholder text of 'Username'", function() {
          return browser.elementByCss("input[name=username]")
          .then(function(el) {
            return browser.getAttribute(el, "placeholder");
          }).should.eventually.equal("Username");
      });
      it("should have a passphrase field", function() {
        return browser
          .waitForElementByCss("input[name=passphrase]")
          .then(function() {
            return browser.elementByCss("input[name=passphrase]");
          }).should.eventually.be.ok;
      });
      it("should have a placeholder text of 'Passphrase'", function() {
        return browser.elementByCss("input[name=passphrase]")
          .then(function(el) {
            return browser.getAttribute(el, "placeholder");
          }).should.eventually.equal("Passphrase");
      });
      it("should already have the username filled in", function() {
        return browser
          .waitForElementByCss("input[name=username]")
          .then(function() {
            return wd.asserters.jsCondition("document.querySelector('input[name=username]').value === '" + newusername + "'");
          }).should.eventually.be.ok;
      });
      it("should display an error when passphrase is empty", function() {
        return browser
          .waitForElementByCss(".button.loginButton")
          .then(function() {
            return $(".button.loginButton").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert:not(.dismissed)");
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert .dialog .title");
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("document.querySelector('.dialogAlert .dialog .subtitle').innerText === 'Must supply username and passphrase'"));
          }).should.eventually.be.ok;
      });
      it("should be able to dismiss the authentication error", function() {
        return browser.noop()
          .then(function() {
            return browser.waitForElementByCss(".dialogAlert .buttons .button.dialog-accept-btn");
          })
          .then(function() {
            return $(".dialogAlert .buttons .button.dialog-accept-btn").click();
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("!!document.querySelector('.dialogAlert.dismissed')"));
          }).should.eventually.be.ok;
      });
      it("should be able to enter a passphrase", function() {
        return browser.noop()
          .then(function() {
            return $('input[name=passphrase]').val(newpassphrase);
          })
          .then(function() {
            return $('input[name=passphrase]').val();
          }).should.eventually.equal(newpassphrase);
      });
      it("should have a login button", function() {
        return browser.noop()
          .then(function() {
            return browser.waitForElementByCss(".loginButton");
          })
          .then(function() {
            return $('.loginButton').text();
          }).should.eventually.equal("Log in");
      });
      it("should be able to log in", function() {
        return browser
          .waitForElementByCss(".loginButton")
          .then(function() {
            return $(".loginButton").click();
          })
          .then(function() {
            return browser
              .waitForElementByCss(".login.dismissed");
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'"));
          })
          .then(function() {
            return $(".emptyEntries").text();
          })
          .then(function(text) {
            return text;
          }).should.eventually.equal("No entries yet\nAdd some now with the '+' above");
      });
    });
// Add entry menu button
    describe("Add entry button and menu", function() {
      it("should have an 'add entries' button", function() {
        return browser
          .waitForElementByCss(".add-btn")
          .then(function() {
            return $(".add-btn i.fa-plus");
          }).should.eventually.be.ok;
      });
      it("should show the add menu when clicked", function() {
        return browser
          .waitForElementByCss(".add-btn")
          .then(function() {
            return $(".add-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".addMenu:not(.dismissed)");
          })
          .then(function() {
            return $(".addMenu:not(.dismissed)");
          }).should.eventually.be.ok;
      });
      it("should show three items in the add menu (General, Credit Card and Password)", function() {
        return browser
          .waitForElementByCss(".addMenu:not(.dismissed)")
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('.addMenu ul li').length === 3"));
          }).should.eventually.be.ok;
      });
      it("should hide the add menu when clicked anywhere else", function() {
        return browser.noop()
          .then(function() {
            return $(".emptyEntries").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".addMenu.dismissed");
          })
          .then(function() {
            return $(".addMenu.dismissed");
          }).should.eventually.be.ok;
      });
    });
// Back out of adding an entry
    describe("Back out of adding an entry", function() {
      before(function() {
        return browser
          .waitForElementByCss(".add-btn")
          .then(function() {
            return $(".add-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".addMenu:not(.dismissed)");
          })
          .then(function() {
            return $(".addMenu li a[data-model=GeneralType]");
          })
          .then(function() {
            return $(".addMenu li a[data-model=GeneralType]").click();
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('input[name=label]')[0].disabled === false"));
          })
          .then(function() {
            return $(".nav .title").text();
          }).should.eventually.equal("General");
      });
      it("should be able to click on the back button and go back", function() {
        return browser
          .waitForElementByCss(".back-btn:not(.hidden)")
          .then(function() {
            return browser.waitForElementByCss(".back-btn:not(.hidden)");
          })
          .then(function() {
            return $(".back-btn").click();
          })
          .then(function() {
            // deal with the confirmation dialog
            return browser.waitForElementByCss(".dialogConfirm:not(.dismissed)");
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogConfirm .dialog .title");
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("document.querySelector('.dialogConfirm .dialog .title').innerText === 'Confirm navigation'"));
          })
          .then(function() {
            return $(".dialogConfirm .buttons .button.dialog-accept-btn").click();
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelector('.nav .title').innerText === 'Encryptr'"));
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'"));
          }).should.eventually.be.ok;
      });
    });
// Add a General entry
    describe("Add a general entry", function() {
      it("should navigate to the edit screen for a General entry", function() {
        return browser
          .waitForElementByCss(".add-btn")
          .then(function() {
            return $(".add-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".addMenu:not(.dismissed)");
          })
          .then(function() {
            return $(".addMenu li a[data-model=GeneralType]");
          })
          .then(function() {
            return $(".addMenu li a[data-model=GeneralType]").click();
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelectorAll('input[name=label]')[0].disabled === false"));
          })
          .then(function() {
            return $(".nav .title").text();
          }).should.eventually.equal("General");
      });
      it("should have a label input", function() {
        return browser
          .waitForElementByCss("input[name=label]")
          .then(function() {
            return browser.elementByCss("input[name=label]");
          }).should.eventually.be.ok;
      });
      it("should have a text input", function() {
        return browser
          .waitForElementByCss("input[name=text]")
          .then(function() {
            return browser.elementByCss("input[name=text]");
          }).should.eventually.be.ok;
      });
      it("should have a placeholder text of 'Text here'", function() {
          return browser.elementByCss("input[name=text]")
          .then(function(el) {
            return browser.getAttribute(el, "placeholder");
          }).should.eventually.equal("Text here");
      });
      it("should be able to enter a label", function() {
        return browser
          .waitFor(wd.asserters.jsCondition("document.querySelectorAll('input[name=label]')[0].disabled === false"))
          .then(function() {
            return $('input[name=label]').val("New general entry");
          })
          .then(function() {
            return $('input[name=label]').val();
          }).should.eventually.equal("New general entry");
      });
      it("should be able to enter a text value", function() {
        return browser
          .waitFor(wd.asserters.jsCondition("document.querySelectorAll('input[name=text]')[0].disabled === false"))
          .then(function() {
            return $('input[name=text]').val("New text value");
          })
          .then(function() {
            return $('input[name=text]').val();
          }).should.eventually.equal("New text value");
      });
      it("should be able to save the new entry", function() {
        return browser
          .waitForElementByCss(".save-btn")
          .then(function() {
            return $(".save-btn").click();
          });
      });
      it("should have saved a new general entry", function() {
        return browser
          .waitForElementByCss("li.entry")
          .then(function() {
            return $("li.entry");
          }).should.eventually.be.ok;
      });
      it("should have the entered label", function() {
        return browser
          .waitForElementByCss("li.entry a > div:first-child")
          .then(function() {
            return $("li.entry a > div:first-child").text();
          }).should.eventually.equal("New general entry");
      });
      it("should be a general entry", function() {
        return browser
          .waitForElementByCss("li.entry")
          .then(function() {
            return browser.waitForElementByCss("li.entry .small");
          })
          .then(function() {
            return $("li.entry .small").text();
          }).should.eventually.equal("General");
      });
    });
// View a general entry
    describe("View a general entry", function() {
      it("should be able to click on an entry and view it", function() {
        return browser
          .waitForElementByCss("li.entry:first-child")
          .then(function() {
            return $("li.entry a:first-child").click();
          })
          .then(function() {
            return browser.waitForElementByCss("ul li strong"); // improve this
          }).should.eventually.be.ok;
      });
      it("should have a label with the correct text", function() {
        return browser
          .waitForElementByCss("ul li strong")
          .sleep(1000)
          .then(function() {
            return $("ul li strong").text();
          }).should.eventually.equal("New general entry");
      });
      it("should have a text value with the correct text", function() {
        return browser
          .waitForElementByCss(".copyable")
          .then(function() {
            return $(".copyable").text();
          }).should.eventually.equal("New text value");
      });
    });
// Back out of viewing an entry
    describe("Back out of viewing an entry", function() {
      it("should be able to click on the back button and go back", function() {
        return browser
          .waitForElementByCss(".back-btn:not(.hidden)")
          .then(function() {
            return browser.waitForElementByCss(".back-btn:not(.hidden)");
          })
          .then(function() {
            return $(".back-btn").click();
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition(
                "document.querySelectorAll('.nav .title')[0].innerText === 'Encryptr'")
              );
          }).should.eventually.be.ok;
      });
    });
// Navigate to an entry and begin editing it
    //describe("Navigate to an entry and begin editing it", function() {
      //before(function() {
        //return browser
          //.waitForElementByCss("li.entry:first-child")
          //.then(function() {
            //return $("li.entry a:first-child").click();
          //})
          //.then(function() {
            //return browser.waitForElementByCss("ul li strong"); // improve this
          //}).should.eventually.be.ok;
      //});
      //it("should have an edit button", function() {
      //});
      //it("should be able to click on the edit button and begin editing", function() {
      //});
    //});
// Back out of editing an entry
    //describe("Back out of editing an entry", function() {
      //it("should be able to click on the back button and go back", function() {
        //return browser
          //.waitForElementByCss(".back-btn:not(.hidden)")
          //.then(function() {
            //return browser.waitForElementByCss(".back-btn:not(.hidden)");
          //})
          //.then(function() {
            //return $(".back-btn").click();
          //})
          //.then(function() {
            //return browser
              //.waitFor(wd.asserters.jsCondition("document.querySelectorAll('.nav .title')[0].innerText === 'Encryptr'"));
          //})
          //.then(function() {
            //return browser
              //.waitFor(wd.asserters.jsCondition("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'"));
          //}).should.eventually.be.ok;
      //});
    //});
// Edit a general entry
    describe("Edit a general entry", function() {
      before(function() {
        // ...
      });
    });
// Delete a general entry
    describe("Delete a general entry", function() {
      it("should navigate to the entry", function() {
        return browser
          .waitForElementByCss("li.entry:first-child")
          .then(function() {
            return $("li.entry a:first-child").click();
          })
          .then(function() {
            return browser.waitForElementByCss("ul li strong"); // improve this
          }).should.eventually.be.ok;
      });
      it("should have a delete button", function() {
        return browser
          .waitForElementByCss(".delete-btn", wd.asserters.isDisplayed)
          .then(function() {
            return $(".delete-btn:not(.hidden)");
          }).should.eventually.be.ok;
      });
      it("should ask for confirmation when delete button clicked", function() {
        return browser
          .waitForElementByCss(".delete-btn", wd.asserters.isDisplayed)
          .then(function() {
            return $(".delete-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogConfirm:not(.dismissed)");
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogConfirm:not(.dismissed) .dialog .title");
          })
          .then(function() {
            return browser.waitFor(wd.asserters.jsCondition("document.querySelector('.dialogConfirm:not(.dismissed) .dialog .title').innerText === 'Confirm delete'"));
          }).should.eventually.be.ok;
      });
      it("should not delete the entry if confirmation cancelled", function() {
        return browser
          .waitForElementByCss(".dialogConfirm:not(.dismissed)")
          .then(function() {
            return browser
              .waitForElementByCss(".dialogConfirm:not(.dismissed) .dialog-cancel-btn");
          })
          .then(function() {
            return $(".dialogConfirm:not(.dismissed) .dialog-cancel-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss("ul li strong", wd.asserters.isDisplayed);
          }).should.eventually.be.ok;
      });
      it("should delete the entry if confirmation accepted", function() {
        return browser
          .waitForElementByCss(".delete-btn", wd.asserters.isDisplayed)
          .then(function() {
            return $(".delete-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogConfirm:not(.dismissed)");
          })
          .then(function() {
            return browser.waitForElementByCss(".dialogConfirm:not(.dismissed) .dialog-accept-btn");
          })
          .then(function() {
            return $(".dialogConfirm:not(.dismissed) .dialog-accept-btn").click();
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelector('.emptyEntries') !== null"));
          })
          .then(function() {
            return browser
              .waitFor(wd.asserters.jsCondition("document.querySelector('.emptyEntries').style.display === 'block'"));
          }).should.eventually.be.ok;
      });
    });
// Add a password entry
    describe("Add a password entry", function() {
      // ...
    });
// View a password entry
    describe("View a password entry", function() {
      // ...
    });
// Copy a password to the clipboard
    describe("Copy a password to the clipboard", function() {
      // ...
    });
// Edit a password entry
    describe("Edit a password entry", function() {
      // ...
    });
// Delete a password entry
    describe("Delete a password entry", function() {
      // ...
    });
// Add a credit card entry
    describe("Add a credit card entry", function() {
      // ...
    });
// View a credit card entry
    describe("View a credit card entry", function() {
      // ...
    });
// Edit a credit card entry
    describe("Edit a credit card entry", function() {
      // ...
    });
// Delete a credit card entry
    describe("Delete a credit card entry", function() {
      // ...
    });
// Log back out
    describe("Log out", function() {
      it("should have a menu button", function() {
        return browser
          .waitForElementByCss(".menu-btn:not(.hidden)")
          .then(function() {
            return $(".menu-btn");
          }).should.eventually.be.ok;
      });
      it("should be able to log out", function() {
        return browser
          .waitForElementByCss(".menu-btn:not(.hidden)")
          .then(function() {
            return $(".menu-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".menu-logout");
          })
          .then(function() {
            return $(".menu-logout").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".login:not(.dismissed)");
          })
          .then(function() {
            return $(".login:not(.dismissed)");
          }).should.eventually.be.ok;
      });
    });
  });
});
