require("mocha-as-promised")();

path = require('path');
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
    appURL = projectRoot + "/platforms/android/bin/Encryptr-debug.apk";
  }
  else {
    appURL = projectRoot + "/platforms/ios/build/emulator/Encryptr.app";
  }

  before(function() {
    browser = wd.promiseChainRemote("localhost", 4723);
    $ = wdQuery(browser);
    return browser
      .init({
        device: (process.env.APPIUM === "android") ? 'Selendroid' : 'iPhone Simulator',
        'app-package'  : (process.env.APPIUM === "android") ? 'org.devgeeks.encryptr' : undefined,
        'app-activity' : (process.env.APPIUM === "android") ? '.Encryptr' : undefined,
        name: "Encryptr",
        platform:'Mac 10.9',
        app: appURL,
        version: '',
        browserName: '',
        implicitWaitMs: 500
      })
      .setAsyncScriptTimeout(30000)
      .windowHandles()
      .then(function(handles) {
        return (process.env.APPIUM === "android") ? browser.window(handles[1]) : browser.window(handles[0]);
      });
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
    describe("registration", function() {
      it("should have a 'Register for an account »' link", function() {
        return browser
          .waitForElementByCss(".signupButton", 100000)
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
          .waitForElementByCss(".signupButton", 100000)
          .then(function() {
            return $(".signupButton").click();
          })
          .then(function() {
            return browser.waitForElementByCss("input[name=newusername]", 100000);
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
          .waitForElementByCss(".button.signupButton", 100000)
          .then(function() {
            return $(".button.signupButton").click();
          })
          .then(function() {
            return browser
              .waitForElementByCss(".login.dismissed", 100000);
          })
          .then(function() {
            return browser
              .waitForConditionInBrowser("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'", 100000);
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
    describe("start over", function() {
      it("should have a menu button", function() {
        return browser
          .waitForElementByCss(".menu-btn", 100000)
          .then(function() {
            return $(".menu-btn");
          }).should.eventually.be.ok;
      });
      it("should be able to log out", function() {
        return browser
          .waitForElementByCss(".menu-btn", 100000)
          .then(function() {
            return $(".menu-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".menu-logout", 100000);
          })
          .then(function() {
            return $(".menu-logout").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".login:not(.dismissed)", 100000);
          })
          .then(function() {
            return $(".loginButton").text();
          }).should.eventually.equal("Log in");
      });
    });
// Log back in
    describe("log in", function() {
      it("should have a username field", function() {
        return browser.noop()
          .then(function() {
            return browser.waitForConditionInBrowser("document.querySelectorAll('input[name=username]')[0].disabled == false", 10000);
          })
          .then(function() {
            return browser.waitForElementByCss("input[name=username]", 100000);
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
          .waitForElementByCss("input[name=passphrase]", 100000)
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
      it("should be able to enter a username", function() {
        return browser
          .waitForConditionInBrowser("document.querySelectorAll('input[name=username]')[0].disabled === false", 100000)
          .then(function() {
            return $('input[name=username]').val(newusername);
          })
          .then(function() {
            return $('input[name=username]').val();
          }).should.eventually.equal(newusername);
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
            return browser.waitForElementByCss(".loginButton", 100000);
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
              .waitForElementByCss(".login.dismissed", 100000);
          })
          .then(function() {
            return browser
              .waitForConditionInBrowser("document.querySelectorAll('.emptyEntries')[0].style.display === 'block'", 100000);
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
    describe("add entry button and menu", function() {
      it("should have an 'add entries' button", function() {
        return browser
          .waitForElementByCss(".add-btn", 100000)
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
            return browser.waitForConditionInBrowser("document.querySelectorAll('.addMenu ul li').length === 3", 100000);
          }).should.eventually.be.ok;
      });
      it("should hide the add menu when clicked anywhere else", function() {
        return browser.noop()
          .then(function() {
            return $(".emptyEntries").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".addMenu.dismissed", 100000);
          })
          .then(function() {
            return $(".addMenu.dismissed");
          }).should.eventually.be.ok;
      });
    });
// Back out of adding an entry
// Add a General entry
    describe("add a general entry", function() {
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
            return browser.waitForConditionInBrowser("document.querySelectorAll('input[name=label]')[0].disabled === false", 100000);
          })
          .then(function() {
            return $(".nav .title").text();
          }).should.eventually.equal("General");
      });
      it("should have a label input", function() {
        return browser
          .waitForElementByCss("input[name=label]", 100000)
          .then(function() {
            return browser.elementByCss("input[name=label]");
          }).should.eventually.be.ok;
      });
      it("should have a text input", function() {
        return browser
          .waitForElementByCss("input[name=text]", 100000)
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
          .waitForConditionInBrowser("document.querySelectorAll('input[name=label]')[0].disabled === false", 100000)
          .then(function() {
            return $('input[name=label]').val("New general entry");
          })
          .then(function() {
            return $('input[name=label]').val();
          }).should.eventually.equal("New general entry");
      });
      it("should be able to enter a text value", function() {
        return browser
          .waitForConditionInBrowser("document.querySelectorAll('input[name=text]')[0].disabled === false", 100000)
          .then(function() {
            return $('input[name=text]').val("New text value");
          })
          .then(function() {
            return $('input[name=text]').val();
          }).should.eventually.equal("New text value");
      });
      it("should be able to save the new entry", function() {
        return browser
          .waitForElementByCss(".save-btn", 100000)
          .then(function() {
            return $(".save-btn").click();
          });
      });
      it("should have saved a new general entry", function() {
        return browser
          .waitForElementByCss("li.entry", 100000)
          .then(function() {
            return $("li.entry");
          }).should.eventually.be.ok;
      });
      it("should have the entered label", function() {
        return browser
          .waitForElementByCss("li.entry a > div:first-child", 100000)
          .then(function() {
            return $("li.entry a > div:first-child").text();
          }).should.eventually.equal("New general entry");
      });
      it("should be a general entry", function() {
        return browser
          .waitForElementByCss("li.entry", 100000)
          .then(function() {
            return browser.waitForElementByCss("li.entry .small", 100000);
          })
          .then(function() {
            return $("li.entry .small").text();
          }).should.eventually.equal("General");
      });
    });
// View a general entry
    describe("view a general entry", function() {
      it("should be able to click on an entry and view it", function() {
        return browser
          .waitForElementByCss("li.entry:first-child", 100000)
          .then(function() {
            return $("li.entry a:first-child").click();
          })
          .then(function() {
            return browser.waitForElementByCss("ul li strong", 100000); // improve this
          }).should.eventually.be.ok;
      });
      it("should have a label with the correct text", function() {
        return browser
          .waitForElementByCss("ul li strong")
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
// THIS EXPOSES THE "BACK POPS ALL OFF THE STACK" BUG!
    describe("back out of viewing an entry", function() {
      it("should be able to click on the back button and go back", function() {
        return browser
          .waitForElementByCss(".back-btn:not(.hidden)", 100000)
          .then(function() {
            return browser.waitForElementByCss(".back-btn:not(.hidden) .fa-arrow-left");
          })
          .then(function() {
            return $(".back-btn:not(.hidden)").click();
          })
          .then(function() {
            return browser.waitForConditionInBrowser("document.querySelectorAll('.nav .title')[0].innerText === 'Encryptr'", 100000);
          }).should.eventually.be.ok;
      });
    });
// Edit a general entry
// Back out of editing an entry
// Delete a general entry
// Add a password entry
// View a password entry
// Copy a password to the clipboard
// Edit a password entry
// Delete a password entry
// Add a credit card entry
// View a credit card entry
// Edit a credit card entry
// Delete a credit card entry
// Log back out
    describe("log out", function() {
      it("should be able to log out", function() {
        return browser
          .waitForElementByCss(".menu-btn", 100000)
          .then(function() {
            return $(".menu-btn").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".menu-logout", 100000);
          })
          .then(function() {
            return $(".menu-logout").click();
          })
          .then(function() {
            return browser.waitForElementByCss(".login:not(.dismissed)", 100000);
          })
          .then(function() {
            return $(".loginButton").text();
          }).should.eventually.equal("Log in");
      });
    });
  });
});