/*jshint expr:true */

describe('Export to Csv', function() {

    window.app = new window.Encryptr();
    var view, csv, entry, entries, fields, csvData;

    beforeEach(function() {
      view = new window.app.MainView();
      entry = {
        type: 'entry_type',
        label: 'entry_label',
        items: [
          {key: 'item_name_1', value: 'value_item_1'}
        ]
      };
      entries = [entry];
      fields = ['Entry Type', 'Label'];
      csvData = {
        'Entry Type': 'entry_type',
        'Label': 'entry_label',
        'item_name_1': 'value_item_1'
      };
      csv = '"Entry Type","Label","item_name_1"\n"entry_type","entry_label","value_item_1"';
    });

    describe('addFieldFromEntry', function() {

      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
      
      it('should have one field in fields', function() {
        fields = [];
        view.addFieldFromEntry(entry, fields);
        fields.should.be.eql(['item_name_1']);
      });
      
      it('should have two field items in fields', function() {
        entry.items.push({key: 'item_name_2'});
        fields = [];
        view.addFieldFromEntry(entry, fields);
        fields.should.be.eql(['item_name_1', 'item_name_2']);
      });

      it('should not add repeat field', function() {
        entry.items.push({key: 'item_name_1'});
        fields = [];
        view.addFieldFromEntry(entry, fields);
        fields.should.be.eql(['item_name_1']);
      });

    });

    describe('getCsvFields', function() {

      it('should have getCsvFields method', function() {
        view.getCsvFields.should.be.an('function');
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
        view.addFieldFromEntry({items: []}, fields);
        fields.should.be.eql(['Entry Type', 'Label']);
      });

      it('should have default fields and entry field in return', function() {
        view.addFieldFromEntry(entry, fields);
        fields.should.be.eql(['Entry Type', 'Label', 'item_name_1']);
      });

      it('should not add repeat field', function() {
        entry = {items: [{key: 'Entry Type'}]};
        entries = [entry];
        view.addFieldFromEntry(entry, fields);
        fields.should.be.eql(['Entry Type', 'Label']);
      });

    });

    describe('addDataFromEntry', function() {
      
      it('should have addDataFromEntry method', function() {
        view.addDataFromEntry.should.be.an('function');
      });

      it('should return correct fields in entry', function() {
        var entry_return = view.addDataFromEntry(entry, fields);
        entry_return.should.have.keys('Entry Type', 'Label', 'item_name_1');
      });

      it('should return correct Entry Type in entry', function() {
        var entry_return = view.addDataFromEntry(entry, fields);
        entry_return['Entry Type'].should.be.eql('entry_type');
      });

      it('should return correct Label in entry', function() {
        var entry_return = view.addDataFromEntry(entry, fields);
        entry_return['Label'].should.be.eql('entry_label');
      });

      it('should return correct item fields in entry', function() {
        var entry_return = view.addDataFromEntry(entry, fields);
        entry_return['item_name_1'].should.be.eql('value_item_1');
      });

    });

    describe('getCsvData', function() {
      it('should have getCsvData method', function() {
        view.getCsvData.should.be.an('function');
      });
    });

    describe('writeCordovaFile', function() {
      it('should have writeCordovaFile method', function() {
        view.writeCordovaFile.should.be.an('function');
      });
    });

    describe('saveCsv', function() {
      it('should have saveCsv method', function() {
        view.saveCsv.should.be.an('function');
      });
    });

    describe('generateCsvFromEntries', function() {
      it('should have generateCsvFromEntries method', function() {
        view.generateCsvFromEntries.should.be.an('function');
      });
    });

    describe('getEntries', function() {
      it('should have getEntries method', function() {
        view.getEntries.should.be.an('function');
      });
    });

    describe('exportButton_clickHandler', function() {
      it('should have addFieldFromEntry method', function() {
        view.addFieldFromEntry.should.be.an('function');
      });
    });

});
