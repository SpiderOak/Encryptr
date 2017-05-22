/*jshint expr:true */

describe('Offline', function() {

  describe('App', function() {

    var events;

    beforeEach(function() {
      events = ['up', 'down', 'confirmed-down', 'confirmed-up'];
      window.app = new window.Encryptr();
      sinon.stub(window.app, 'setOffline');
      sinon.stub(window.app, 'setOnline');
      window.app.init();
    });

    afterEach(function() {
      window.app.setOffline.restore();
      window.app.setOnline.restore();
    });

    describe('offline module (offlineJs)', function() {

      describe('should have handler method', function(){

        beforeEach(function() {
          events = ['up', 'down', 'confirmed-down', 'confirmed-up'];
          window.app = new window.Encryptr();
          sinon.stub(window.app, 'setOffline');
          sinon.stub(window.app, 'setOnline');
          sinon.stub(window.Offline, 'on');
          window.app.init();
        });

        afterEach(function() {
          window.Offline.on.restore();
        });

        it('up', function() {
          window.Offline.on.calledWith('up').should.be.true();
        });

        it('down', function() {
          window.Offline.on.calledWith('down').should.be.true();
        });

        it('confirmed-up', function() {
          window.Offline.on.calledWith('confirmed-up').should.be.true();
        });

        it('confirmed-down', function() {
          window.Offline.on.calledWith('confirmed-down').should.be.true();
        });

      });

      it('should call setOnline mehod in up event', function() {
        window.Offline.markUp();
        window.app.setOnline.called.should.be.true();
      });

      it('should call setOnline mehod in confirmed-up event', function() {
        window.Offline.markUp();
        window.app.setOnline.called.should.be.true();
      });

      it('should call setOffline mehod in confirmed-down event', function() {
        window.Offline.markDown();
        window.app.setOffline.called.should.be.true();
      });

      it('should call setOffline mehod in down event', function() {
        window.Offline.markDown();
        window.app.setOffline.called.should.be.true();
      });

    });

    describe('loadOfflineData', function(){

      var data, file, original_sessionStorage, promose_function;

      beforeEach(function() {
        promise_function = function() {
          var promise = $.Deferred();
          promise.resolve(data);
          return promise;
        };
        data = 'data';
        file = 'encrypt.data';
        original_sessionStorage = JSON.parse(JSON.stringify(window.sessionStorage));
        window.sessionStorage.setItem = sinon.stub().returns(promise_function());
        window.sessionStorage.getItem = sinon.stub().returns(null);
      });

      afterEach(function() {
          window.sessionStorage = original_sessionStorage;
        });

      it('should have loadOfflineData method', function() {
        window.app.loadOfflineData.should.be.an('function');
      });

      describe('ios, andriod or bb10', function() {

        beforeEach(function() {
          $.os.ios = true;
          $.os.andriod = true;
          $.os.bb10 = true;
          sinon.stub(window.app, 'readOfflineDataCordova', promise_function);
        });

        afterEach(function() {
          $.os.ios = false;
          $.os.andriod = false;
          $.os.bb10 = false;
          window.app.readOfflineDataCordova.restore();
        });

        it('should call readOfflineDataCordova method', function(done) {
          window.app.loadOfflineData().then(function() {
            window.app.readOfflineDataCordova.called.should.be.true();
          }).then(done);
        });

        it('should call readOfflineDataCordova method with correct params', function(done) {
          window.app.loadOfflineData().then(function() {
            window.app.readOfflineDataCordova.calledWith(file).should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.setItem method', function(done) {
          window.app.loadOfflineData().then(function() {
            window.sessionStorage.setItem.called.should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.setItem method with correct params', function(done) {
          window.app.loadOfflineData().then(function() {
            window.sessionStorage.setItem.calledWith('crypton', data).should.be.true();
          }).then(done);
        });

      });

      describe('desktop', function() {
        
        beforeEach(function() {
          $.os.nodeWebkit = true;
          sinon.stub(window.app, 'readOfflineDataInDesktop', promise_function);
        });

        afterEach(function() {
          $.os.nodeWebkit = false;
          window.app.readOfflineDataInDesktop.restore();
        });

        it('should call readOfflineDataInDesktop method', function(done) {
          window.app.loadOfflineData().then(function() {
            window.app.readOfflineDataInDesktop.called.should.be.true();
          }).then(done);
        });

        it('should call readOfflineDataInDesktop method with correct params', function(done) {
          window.app.loadOfflineData().then(function() {
            window.app.readOfflineDataInDesktop.calledWith(file).should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.setItem method', function(done) {
          window.app.loadOfflineData().then(function() {
            window.sessionStorage.setItem.called.should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.setItem method with correct params', function(done) {
          window.app.loadOfflineData().then(function() {
            window.sessionStorage.setItem.calledWith('crypton', data).should.be.true();
          }).then(done);
        });

      });

    });

    describe('readCordovaFile', function(){

      var directory;

      beforeEach(function() {
        directory = 'cdb:///files/';
        window.resolveLocalFileSystemURL = sinon.stub();
      });

      afterEach(function() {
        window.resolveLocalFileSystemURL = undefined;
      });

      it('should have readCordovaFile method', function() {
        window.app.readCordovaFile.should.be.an('function');
      });

      it('should call window.resolveLocalFileSystemURL method', function(){
        window.app.readCordovaFile(directory);
        window.resolveLocalFileSystemURL.called.should.be.true();
      });

      it('should call window.resolveLocalFileSystemURL method with correct params', function(){
        window.app.readCordovaFile(directory);
        window.resolveLocalFileSystemURL.calledWith(directory).should.be.true();
      });

    });

    describe('readOfflineDataCordova', function(){

      var file;

      beforeEach(function() {
        fiel = 'encryptr.data';
        sinon.stub(window.app, 'readCordovaFile');
      });

      afterEach(function() {
        window.app.readCordovaFile.restore();
      });

      it('should have readOfflineDataCordova method', function() {
        window.app.readOfflineDataCordova.should.be.an('function');
      });

      it('should have readOfflineDataCordova method', function() {
        window.app.readOfflineDataCordova(file);
        window.app.readCordovaFile.called.should.be.true();
      });

      it('should have readOfflineDataCordova method with correct params', function() {
        window.app.readOfflineDataCordova(file);
        window.app.readCordovaFile.calledWith(cordova.file.dataDirectory, file).should.be.true();
      });

    });

    describe('readOfflineDataInDesktop', function(){

      var filePath, file;

      beforeEach(function() {
        file = 'encryptr.data'
        filePath = 'file://filePath';
        require = sinon.stub().returns({
          join: sinon.stub().returns(filePath),
          readFile: sinon.stub(),
          App: {
            dataPath: 'dataPath'
          }
        });
      });

      afterEach(function() {
        require = undefined;
      });

      it('should have readOfflineDataInDesktop method', function() {
        window.app.readOfflineDataInDesktop.should.be.an('function');
      });

      it('should call require nw.gui', function() {
        window.app.readOfflineDataInDesktop(file);
        require.calledWith('nw.gui').should.be.true();
      });

      it('should call require fs', function() {
        window.app.readOfflineDataInDesktop(file);
        require.calledWith('fs').should.be.true();
      });

      it('should call require path', function() {
        window.app.readOfflineDataInDesktop(file);
        require.calledWith('path').should.be.true();
      });

      it('should call path.join', function() {
        window.app.readOfflineDataInDesktop(file);
        require('path').join.called.should.be.true();
      });

      it('should call path.join with correct params', function() {
        var nw = require('nw.gui');
        window.app.readOfflineDataInDesktop(file);
        require('path').join.calledWith(nw.App.dataPath, file).should.be.true();
      });

      it('should call fs.readFile', function() {
        window.app.readOfflineDataInDesktop(file);
        require('fs').readFile.called.should.be.true();
      });

      it('should call fs.readFile', function() {
        window.app.readOfflineDataInDesktop(file);
        require('fs').readFile.calledWith(filePath, 'utf8').should.be.true();
      });

    });

    describe('checkonline', function(){

      var buttons;

      beforeEach(function() {
        window.app.offline_btns = [];
        window.app.online = true;
        buttons = ['btn1', 'btn2'];
      });

      it('should have checkonline method', function() {
        window.app.checkonline.should.be.an('function');
      });

      it('should add btns to offline_btns', function() {
        window.app.checkonline(buttons);
        window.app.offline_btns.should.be.eql(buttons);
      });

      it('should add btns to offline_btns and not repeat', function() {
        window.app.checkonline(buttons);
        window.app.checkonline(buttons);
        window.app.offline_btns.should.be.eql(buttons);
      });

      it('should call setOnline when online is true', function() {
        window.app.checkonline(buttons);
        window.app.setOnline.called.should.be.true();
      });

      it('should call setOffline when online is false', function() {
        window.app.online = false;
        window.app.checkonline(buttons);
        window.app.setOffline.called.should.be.true();
      });

    });

    describe('setOffline', function(){

      beforeEach(function() {
        window.app.setOffline.restore();
        window.app.setOnline.restore();
      });

      afterEach(function() {
        sinon.stub(window.app, 'setOffline');
        sinon.stub(window.app, 'setOnline');
      });

      it('should have setOffline method', function() {
        window.app.setOffline.should.be.an('function');
      });

      it('should set online in false', function() {
        window.app.setOffline();
        window.app.online.should.be.false();
      });

      it('should set window.crypton.online in false', function() {
        window.app.setOffline();
        window.crypton.online.should.be.false();
      });

      it('should set window.online in false', function() {
        window.app.setOffline();
        window.online.should.be.false();
      });

      it('should call loadOfflineData when getItem is null', function() {
        sinon.stub(app, 'loadOfflineData');
        window.app.setOffline();
        app.loadOfflineData.called.should.be.true();
        app.loadOfflineData.restore();
      });

    });

    describe('setOnline', function(){

      beforeEach(function() {
        window.app.setOffline.restore();
        window.app.setOnline.restore();
      });

      afterEach(function() {
        sinon.stub(window.app, 'setOffline');
        sinon.stub(window.app, 'setOnline');
      });

      it('should have setOnline method', function() {
        window.app.setOnline.should.be.an('function');
      });

      it('should set online in true', function() {
        window.app.setOnline();
        window.app.online.should.be.true();
      });

      it('should set window.crypton.online in true', function() {
        window.app.setOnline();
        window.crypton.online.should.be.true();
      });

      it('should set window.online in true', function() {
        window.app.setOnline();
        window.online.should.be.true();
      });

    });

  });

  describe('DialogConfirmView (DialogView.js)', function() {

    it('should call app.checkonline method in initialize', function() {
      sinon.stub(app, 'checkonline');
      try {
        new window.app.DialogConfirmView();
      } catch(e) {
        app.checkonline.called.should.be.true();
      }
      app.checkonline.restore();
    });

  });

  describe('EditView', function() {

    it('should call app.checkonline method in initialize', function() {
      sinon.stub(app, 'checkonline');
      try {
        new window.app.EditView();
      } catch(e) {
        app.checkonline.called.should.be.true();
      }
      app.checkonline.restore();
    });

  });

  describe('EntryView', function() {

    it('should call app.checkonline method in initialize', function() {
      sinon.stub(app, 'checkonline');
      try {
        new window.app.EntryView();
      } catch(e) {
        app.checkonline.called.should.be.true();
      }
      app.checkonline.restore();
    });

  });

  describe('SettingView', function() {

    it('should call app.checkonline method in initialize', function() {
      sinon.stub(app, 'checkonline');
      try {
        new window.app.SettingsView();
      } catch(e) {
        app.checkonline.called.should.be.true();
      }
      app.checkonline.restore();
    });

  });

  describe('MainView', function() {

    var view;

    beforeEach(function() {
      $.os.nodeWebkit = false;
      $.os.android = false;
      $.os.ios = false;
      $.os.bb10 = false;
      view = new window.app.MainView();
      sinon.stub(view, 'updateLocalStorage', promise_function);
    });

    it('should call app.checkonline method in initialize', function() {
      sinon.stub(app, 'checkonline');
      try {
        new window.app.MainView();
      } catch(e) {
        app.checkonline.called.should.be.true();
      }
      app.checkonline.restore();
    });

    it('should call updateLocalStorage method in initialize', function() {
      $.os.nodeWebkit = true;
      view.initialize();
      view.updateLocalStorage.called.should.be.true();
    });

    describe('updateLocalStorage', function(){

      var file, data;

      beforeEach(function() {
        file = 'encrypt.data';
        data = null;
        sinon.stub(view, 'getEntries', promise_function);
	view.updateLocalStorage.restore();
      });

      afterEach(function() {
        view.getEntries.restore();
      });

      it('should have updateLocalStorage method', function() {
        view.updateLocalStorage.should.be.an('function');
      });

      describe('ios, andriod or bb10', function() {

        beforeEach(function() {
          $.os.ios = true;
          $.os.andriod = true;
          $.os.bb10 = true;
          sinon.stub(view, 'saveOfflineDataCordova', promise_function);
        });

        afterEach(function() {
          $.os.ios = false;
          $.os.andriod = false;
          $.os.bb10 = false;
          view.saveOfflineDataCordova.restore();
        });

        it('should call saveOfflineDataCordova method', function(done) {
          view.updateLocalStorage().then(function() {
            view.saveOfflineDataCordova.called.should.be.true();
          }).then(done);
        });

        it('should call saveOfflineDataCordova method with correct params', function(done) {
          view.updateLocalStorage().then(function() {
            view.saveOfflineDataCordova.calledWith(file, data).should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.getItem method', function(done) {
          view.updateLocalStorage().then(function() {
            window.sessionStorage.getItem.called.should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.getItem method with correct params', function(done) {
          view.updateLocalStorage().then(function() {
            window.sessionStorage.setItem.calledWith('crypton').should.be.true();
          }).then(done);
        });

      });

      describe('desktop', function() {

        beforeEach(function() {
          $.os.nodeWebkit = true;
          sinon.stub(view, 'saveOfflineDataInDesktop', promise_function);
        });

        afterEach(function() {
          $.os.nodeWebkit = false;
          view.saveOfflineDataInDesktop.restore();
        });

        it('should call saveOfflineDataInDesktop method', function(done) {
          view.updateLocalStorage().then(function() {
            view.saveOfflineDataInDesktop.called.should.be.true();
          }).then(done);
        });

        it('should call saveOfflineDataInDesktop method with correct params', function(done) {
          view.updateLocalStorage().then(function() {
            view.saveOfflineDataInDesktop.calledWith(file, data).should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.getItem method', function(done) {
          view.updateLocalStorage().then(function() {
            window.sessionStorage.getItem.called.should.be.true();
          }).then(done);
        });

        it('should call window.sessionStorage.getItem method with correct params', function(done) {
          view.updateLocalStorage().then(function() {
            window.sessionStorage.getItem.calledWith('crypton').should.be.true();
          }).then(done);
        });

      });

    });

    describe('saveOfflineDataInDesktop', function(){

      var filePath, file, data;

      beforeEach(function() {
        file = 'encryptr.data';
        data = 'data';
        filePath = 'file://filePath';
        require = sinon.stub().returns({
          join: sinon.stub().returns(filePath),
          writeFile: sinon.stub(),
          App: {
            dataPath: 'dataPath'
          }
        });
      });

      afterEach(function() {
        require = undefined;
      });


      it('should have saveOfflineDataInDesktop method', function() {
        view.saveOfflineDataInDesktop.should.be.an('function');
      });

      it('should have saveOfflineDataInDesktop method', function() {
        view.saveOfflineDataInDesktop.should.be.an('function');
      });

      it('should call require nw.gui', function() {
        view.saveOfflineDataInDesktop(file, data);
        require.calledWith('nw.gui').should.be.true();
      });

      it('should call require fs', function() {
        view.saveOfflineDataInDesktop(file, data);
        require.calledWith('fs').should.be.true();
      });

      it('should call require path', function() {
        view.saveOfflineDataInDesktop(file, data);
        require.calledWith('path').should.be.true();
      });

      it('should call path.join', function() {
        view.saveOfflineDataInDesktop(file, data);
        require('path').join.called.should.be.true();
      });

      it('should call path.join with correct params', function() {
        var nw = require('nw.gui');
        view.saveOfflineDataInDesktop(file, data);
        require('path').join.calledWith(nw.App.dataPath, file).should.be.true();
      });

      it('should call fs.writeFile', function() {
        view.saveOfflineDataInDesktop(file, data);
        require('fs').writeFile.called.should.be.true();
      });

      it('should call fs.writeFile', function() {
        view.saveOfflineDataInDesktop(file, data);
        require('fs').writeFile.calledWith(filePath, data).should.be.true();
      });

    });

    describe('saveOfflineDataCordova', function(){

      var file, data;

      beforeEach(function() {
        file = 'encryptr.data';
        data = 'data';
        sinon.stub(view, 'writeCordovaFile');
      });

      afterEach(function() {
        view.writeCordovaFile.restore();
      });

      it('should have saveOfflineDataCordova method', function() {
        view.saveOfflineDataCordova.should.be.an('function');
      });

      it('should have writeCordovaFile method', function() {
        view.saveOfflineDataCordova(file, data);
        view.writeCordovaFile.called.should.be.true();
      });

      it('should have writeCordovaFile method with correct params', function() {
        view.saveOfflineDataCordova(file, data);
        view.writeCordovaFile.calledWith(cordova.file.dataDirectory, file, data).should.be.true();
      });

    });

  });

});
