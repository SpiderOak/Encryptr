/*jshint expr:true */
describe('Application setup', function() {
  describe('components', function() {

    describe('zepto', function() {
      it('should have zepto', function() {
        window.$.should.be.a('function');
        // not only should $ exist, but $ should be Zepto, not jQuery...
        window.$.should.equal(window.Zepto);
      });
    });

    describe('underscore', function() {
      it('should have underscore', function() {
        window._.should.be.a('function');
      });
    });

    describe('backbone', function() {
      it('should have backbone', function() {
        window.Backbone.should.be.an('object');
      });
    });

    describe('crypton', function() {
      it('should have crypton', function() {
        window.crypton.should.be.an('object');
      });
    });

    describe('sinon', function() {
      it('should have sinon', function() {
        window.sinon.should.be.an('object');
      });
      it('should have sinon spies', function() {
        window.sinon.spy.should.be.a('function');
      });
      it('should have sinon mocks', function() {
        window.sinon.mock.should.be.a('function');
      });
      it('should have sinon stubs', function() {
        window.sinon.stub.should.be.a('function');
      });
    });

    describe('json2csv', function() {
      it('should have json2csv', function() {
        json2csv.should.be.an('function');
      });
    });

  });

  describe('initialize', function() {
    window.app = new window.Encryptr();
    beforeEach(function() {
      sinon.spy(window.app, "onDeviceReady");
    });
    afterEach(function() {
      window.app.onDeviceReady.restore();
    });
    it('should have Encryptr', function() {
      window.Encryptr.should.be.a('function');
    });
    it('should have app', function() {
      window.app.should.be.an('object');
    });
    it('should bind deviceready', function() {
      window.app.init();
      helper.trigger(window.document,'deviceready');
      window.app.onDeviceReady.called.should.equal(true);
    });
  });

});


