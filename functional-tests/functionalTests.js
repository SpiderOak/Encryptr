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
  this.timeout(30000);
  var browser;
  var appURL;
  var $;

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
      .windowHandles()
      .then(function(handles) {
        return (process.env.APPIUM === "android") ? browser.window(handles[1]) : browser.window(handles[0]);
      });
  });

  // using mocha-as-promised and chai-as-promised is the best way
  describe("Login", function() {

    beforeEach(function() {
      // ...
    });

    after(function() {
      return browser
        .quit();
    });

    describe("logging in", function() {
      it("should have a username field", function() {
        return browser
          .waitForElementByCss("input[name=username]", 10000)
          .then(function() {
            return browser.elementByCss("input[name=username]");
          });
      });
      it("should have a placeholder text of 'Username'", function() {
          return browser.elementByCss("input[name=username]")
          .then(function(el) {
            return browser.getAttribute(el, "placeholder");
          }).should.eventually.equal("Username");
      });
      it("should have a passphrase field", function() {
        return browser
          .waitForElementByCss("input[name=passphrase]", 10000)
          .then(function() {
            return browser.elementByCss("input[name=passphrase]");
          });
      });
      it("should have a placeholder text of 'Passphrase'", function() {
          return browser.elementByCss("input[name=passphrase]")
          .then(function(el) {
            return browser.getAttribute(el, "placeholder");
          }).should.eventually.equal("Passphrase");
      });
      it("should be able to enter a username", function() {
        return browser.noop()
          .then(function() {
            return $('input[name=username]').val('test1');
          })
          .then(function() {
            return $('input[name=username]').val();
          }).should.eventually.equal("test1");
      });
      it("should be able to enter a password", function() {
        return browser.noop()
          .then(function() {
            return $('input[name=passphrase]').val('pass1234');
          })
          .then(function() {
            return $('input[name=passphrase]').val();
          }).should.eventually.equal("pass1234");
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
            return browser.waitForElementByCss(".entriesViewLoading", 100000);
          })
          .then(function() {
            return $(".entriesViewLoading").text();
          }).should.eventually.be.ok;
      });
    });
    describe("logging out", function() {
      it("should be able to log out", function() {
        return browser
          .waitForElementByCss(".menu-btn")
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