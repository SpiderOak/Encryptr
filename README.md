Encryptr
========

[Encryptr](http://encryptr.devgeeks.org) is a zero-knowledge, cloud-based e-wallet / password manager powered by Crypton.

It started as an example project for seeing what [Crypton](https://crypton.io) could do in a [Apache Cordova](http://cordova.apache.org) mobile app. I had a particular itch to scratch. I got tired of trynig to remember my work password. It changes fairly often, is slightly complex and is generated – I can't choose it for myself.

I had tried a few password managers but hadn't loved any of them – particularly on Android. So, when I needed an idea of an app to make to try out Crypton, this seemed like an obvious choice. At its simplest, Crypton is basically a cloud based key/value store using end to end zero-knowledge encryption. None of the data stored on the server can be viewed by the server.

I wanted something to store hard to remember passwords, important numbers, etc across devices. 

Encryptr keeps it simple. It has three types of data it can store. Passwords, Credit Card numbers and general key/value pairs. It can easily be expanded to include other default entry types.

It is currently working on iOS, Android, and the Desktop – thanks to [node-webkit](https://github.com/rogerwang/node-webkit) – but there are no reasons why it could not by expanded to Blackberry10 and Windows Phone 8.

![screenshot](http://f.cl.ly/items/2n1r3V1D0L3k3p1q2T2O/encryptr-screenshot.png)

## Requirements

- Cordova CLI - [https://github.com/apache/cordova-cli/](https://github.com/apache/cordova-cli/)
	- Cordova / PhoneGap command line interface
- Grunt - [http://gruntjs.com/](http://gruntjs.com/)
	- Build tool for minimising, running and tests
- Node and npm - [http://nodejs.org/](http://nodejs.org/)
	- Node package manager for Grunt Add-ons
- PhantomJS - [http://phantomjs.org/](http://phantomjs.org/)
	- Headless webkit for running tests

## Getting started

- clone the project
- cd into the project folder
- `npm install` to install node_modules and js/css components (`npm install` will also run `bower install`).
- `cordova platform add ios` and/or `cordova platform add android`
- `npm run pluginstall` to install any plugins needed

## First test

To make sure everything is set up from the above, run your first tests:

   `grunt test`

See the output for the steps taken to produce the working test rig. Most of the steps have `grunt` commands you can use to do them individually.

## Workflow

JavaScript files are in `src`. They are kept out of the www tree so that they can be linted without trying to lint the concatenated and minified versions. However, the index.html should have a script tag only for the JavaScript files in either `components` (managed by Bower) or `www/js`.

Building and testing the project is normally done via the Grunt tasks below.

## Grunt tasks

We use `grunt` commands to do most of the project operations, like:

* running the app:
** ios: `grunt debug:ios`
** Android: `grunt debug:android`

* testing: `grunt test`
* linting the sources: `grunt jshint`
* concatenating the sources: `grunt concat`
* compiling the templates: `grunt dot`

See the steps taken for `grunt test` and `grunt debug:XXX` for the various operations needed to constitute the working app, and look at Gruntfile.js for the whole repertoire.


### License
- GPLv3 – [https://github.com/devgeeks/Encryptr/blob/master/LICENSE](https://github.com/devgeeks/Encryptr/blob/master/LICENSE)
