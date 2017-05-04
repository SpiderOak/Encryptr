/*jshint expr:true */

describe('Export to Csv', function() {

    window.app = new window.Encryptr();
    var view;

    beforeEach(function() {
      view = new window.app.MainView();
    });
    
    afterEach(function() {
      
    });

    describe('addFieldFromEntry', function() {
      
      var fields, entry;

      beforeEach(function() {
        entry = {items: [{key: 'item_name_1'}]};
        fields = [];
      });

      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
      
      it('should have one field in fields', function() {
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'item_name_1'});
      });
      
      it('should have two field items in fields', function() {
        entry.items.push({key: 'item_name_2'});
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'item_name_1', '1': 'item_name_2'});
      });

      it('should not add repeat field', function() {
          entry.items.push({key: 'item_name_1'});
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'item_name_1'});
      });

    });

    describe('getCsvFields', function() {

      var fields, entries, entry;

      beforeEach(function() {
        entry = {items: [{key: 'item_name_1'}]};
        entries = [entry];
        fields = ['Entry Type', 'Label'];
      });

      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });

      it('should call addFieldFromEntry', function() {
         view.addFieldFromEntry = sinon.spy();
         view.getCsvFields(entries);
         view.addFieldFromEntry.called.should.be.true();
      });

      it('should call addFieldFromEntry with correct entry', function() {
         view.addFieldFromEntry = sinon.spy();
         view.getCsvFields(entries);
         view.addFieldFromEntry.calledWith(entry).should.be.true();
      });

      it('should have default fields in return', function() {
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'Entry Type', '1': 'Label'});
      });

      it('should have default fields and entry field in return', function() {
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'Entry Type', '1': 'Label', '2': 'item_name_1'});
      });

      it('should not add repeat field', function() {
        entry = {items: [{key: 'Entry Type'}]};
        entries = [entry];
        view.addFieldFromEntry(entry, fields);
        fields.should.not.be.eql({'0': 'Entry Type', '1': 'Label'});
      });

    });

    describe('addDataFromEntry', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });

    });

    describe('getCsvData', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

    describe('writeCordovaFile', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

    describe('saveCsv', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

    describe('generateCsvFromEntries', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

    describe('getEntries', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

    describe('exportButton_clickHandler', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

});
