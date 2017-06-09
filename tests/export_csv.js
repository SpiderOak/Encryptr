/*jshint expr:true */

describe('Export to Csv', function() {

    window.app = new window.Encryptr();
    var view, csv, entry, entries, fields, csvData, promise_function;

    beforeEach(function() {
      view = new window.app.MainView();
      promise_function = function(data_return) {
        function promise_revolved() {
          var promise = $.Deferred();
          promise.resolve(data_return);
          return promise;
        }
        return promise_revolved;
      };
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
      window.app.entriesView = {
        getCollection: sinon.stub().returns(promise_function(entries)())
      };
    });

    afterEach(function() {
      window.app.entriesView = undefined;
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

      beforeEach(function() {
        view.addDataFromEntry = sinon.stub().returns(csvData);
      });

      it('should have getCsvData method', function() {
        view.getCsvData.should.be.an('function');
      });

      it('should return correct dict', function() {
        var csvdata = view.getCsvData(entries, fields);
        csvdata.should.be.eql([csvData]);
      });

      it('should call addDataFromEntry', function() {
        view.getCsvData(entries, fields);
        view.addDataFromEntry.called.should.be.true();
      });

      it('should call addDataFromEntry with correct params', function() {
        view.getCsvData(entries, fields);
        view.addDataFromEntry.calledWith(entry, fields).should.be.true();
      });

    });

    describe('generateCsvFromEntries', function() {
      
      beforeEach(function() {
        view.getCsvFields = sinon.spy(function (){
          return fields;
        });
        view.getCsvData = sinon.spy(function (){
          return csvData;
        });
        json2csv = sinon.spy(function (){
          return csv;
        });
      });

      it('should have generateCsvFromEntries method', function() {
        view.generateCsvFromEntries.should.be.an('function');
      });

      it('should call getCsvFields', function() {
        view.generateCsvFromEntries(entries);
        view.getCsvFields.called.should.be.true();
      });

      it('should call getCsvFields with correct params', function() {
        view.generateCsvFromEntries(entries);
        view.getCsvFields.calledWith(entries).should.be.true();
      });

      it('should call getCsvData', function() {
        view.generateCsvFromEntries(entries);
        view.getCsvData.called.should.be.true();
      });

      it('should call getCsvData with correct params', function() {
        view.generateCsvFromEntries(entries);
        view.getCsvData.calledWith(entries, fields).should.be.true();
      });

      it('should call json2csv', function() {
        view.generateCsvFromEntries(entries);
        json2csv.called.should.be.true();
      });

      it('should call json2csv with correct params', function() {
        view.generateCsvFromEntries(entries);
        json2csv.calledWith({'data': csvData, 'fields': fields}).should.be.true();
      });

      it('should return csv from json2csv', function() {
        var csv_returned = view.generateCsvFromEntries(entries);
        csv_returned.should.be.eql(csv);
      });

    });

    describe('getEntry', function() {

      var EntryModelSpy;

      beforeEach(function() {
        EntryModelSpy = sinon.stub(window.app.EntryModel.prototype, 'fetch', function(options){
          options.success('obj', 'resp');
        });
      });

      afterEach(function() {
        EntryModelSpy.restore();
      });

      it('should have getEntry method', function() {
        view.getEntry.should.be.an('function');
      });

      it('should call window.app.EntryModel.fetch', function() {
        view.getEntry();
        EntryModelSpy.called.should.be.true();
      });
      
      it('should promise resolve with success callback resp', function(done) {
        view.getEntry().then(function(resp){
          resp.should.be.eql('resp');
        }).then(done);
      });

    });

    describe('getEntries', function() {

      var collection;

      beforeEach(function() {
        collection = entries;
        view.getEntry = sinon.stub().returns(promise_function(entry)());
        view.getEntryRec = sinon.stub().returns(promise_function(entry)());
        window.app.entriesView.getCollection = sinon.stub().returns(promise_function(entries)());
        window.requestAnimationFrame = sinon.spy();
      });

      it('should have getEntries method', function() {
        view.getEntries.should.be.an('function');
      });

      it('should call window.app.entriesView.getCollection', function() {
        view.getEntries();
        window.app.entriesView.getCollection.called.should.be.true();
      });

      it('should not call getEntry when this.updatedLocalStorage is false', function() {
        view.updatedLocalStorage = false;
        view.getEntries();
        view.getEntry.called.should.be.false();
      });

      it('should call getEntryRec this.updatedLocalStorage is false', function() {
        view.updatedLocalStorage = false;
        view.getEntries();
        view.getEntryRec.called.should.be.true();
      });

      it('should call getEntryRec with correct params this.updatedLocalStorage is false', function() {
        view.updatedLocalStorage = false;
        view.getEntries();
        view.getEntryRec.calledWith(entries, []).should.be.true();
      });

    });

    describe('getCsv', function() {

      beforeEach(function() {
        sinon.stub(view, 'getEntries', function() {
          var promise = $.Deferred();
          promise.resolve(entry);
          return $.when.apply($, [promise]);
        });
        window.app.entriesView.getCollection = view.getEntries;
        sinon.stub(view, 'generateCsvFromEntries').returns('generateCsvFromEntries');
      });

      it('should have getCsv method', function() {
        view.getCsv.should.be.an('function');
      });

      it('should not call getEntries', function() {
        view.getCsv();
        view.getEntries.called.should.be.true();
      });

      it('should not call generateCsvFromEntries', function(done) {
        view.getCsv().then(function() {
          view.generateCsvFromEntries.called.should.be.true();
        }).then(done);
      });

    });

    describe('Methods for iOS and Android plataforms', function() {
      
      describe('writeCordovaFile', function() {

        var filename;

        beforeEach(function() {
          filename = 'export.csv';
          cordova.file = {
            cacheDirectory: 'csb://cahe'
          };
          window.resolveLocalFileSystemURL = sinon.stub();
        });

        afterEach(function() {
          window.resolveLocalFileSystemURL = undefined;
        });

        it('should have writeCordovaFile method', function() {
          view.writeCordovaFile.should.be.an('function');
        });

        it('should call window.resolveLocalFileSystemURL', function() {
          view.writeCordovaFile(filename, csvData);
          window.resolveLocalFileSystemURL.called.should.be.true();
        });

      });

      describe('copyButton_clickHandler', function() {

        var event;

        beforeEach(function() {
          event = {
            stopPropagation: sinon.spy(),
            stopImmediatePropagation: sinon.spy(),
          };
          sinon.stub(view, 'getCsv', promise_function(csv));
          cordova.plugins = {
            clipboard: {
              copy: sinon.spy()
            }
          };
          window.app.toastView = {
            show: sinon.spy()
          };
        });

        it('should have copyButton_clickHandler method', function() {
          view.copyButton_clickHandler.should.be.an('function');
        });

        it('should call event.stopPropagation', function() {
          view.copyButton_clickHandler(event);
          event.stopPropagation.called.should.be.true();
        });

        it('should call event.stopImmediatePropagation', function() {
          view.copyButton_clickHandler(event);
          event.stopImmediatePropagation.called.should.be.true();
        });

        it('should call getCsv', function() {
          view.copyButton_clickHandler(event);
          view.getCsv.called.should.be.true();
        });

        it('should call cordova.plugins.clipboard.copy', function(done) {
          view.copyButton_clickHandler(event).then(function() {
            cordova.plugins.clipboard.copy.called.should.be.true();
          }).then(done);
        });

        it('should call cordova.plugins.clipboard.copy with correct params', function(done) {
          view.copyButton_clickHandler(event).then(function() {
            cordova.plugins.clipboard.copy.calledWith(csv).should.be.true();
          }).then(done);
        });

        it('should call window.app.toastView.show', function(done) {
          view.copyButton_clickHandler(event).then(function() {
            window.app.toastView.show.called.should.be.true();
          }).then(done);
        });

        it('should call window.app.toastView.show with correct message', function(done) {
          var message = "The entries were successfully copied in clipboard";
          view.copyButton_clickHandler(event).then(function() {
            window.app.toastView.show.calledWith(message).should.be.true();
          }).then(done);
        });

      });
      
      describe('shareButton_clickHandler', function() {
        
        var event, filePath;

        beforeEach(function() {
          filePath = '/tmp/export.csv';
          event = {
            stopPropagation: sinon.spy(),
            stopImmediatePropagation: sinon.spy(),
          };
          sinon.stub(view, 'getCsv', promise_function(csv));
          sinon.stub(view, 'writeCordovaFile', promise_function(filePath));
          cordova.file = {
            cacheDirectory: 'cdb://mobile'
          };
          window.plugins = {
            socialsharing: {
              shareWithOptions: sinon.spy()
            }
          };
        });

        it('should have shareButton_clickHandler method', function() {
          view.shareButton_clickHandler.should.be.an('function');
        });

        it('should call event.stopPropagation', function() {
          view.shareButton_clickHandler(event);
          event.stopPropagation.called.should.be.true();
        });

        it('should call event.stopImmediatePropagation', function() {
          view.shareButton_clickHandler(event);
          event.stopImmediatePropagation.called.should.be.true();
        });

        it('should call getCsv', function() {
          view.shareButton_clickHandler(event);
          view.getCsv.called.should.be.true();
        });

        it('should call writeCordovaFile', function(done) {
          view.shareButton_clickHandler(event).then(function() {
            view.writeCordovaFile.called.should.be.true();
          }).then(done);
        });

        it('should call writeCordovaFile with correct params', function(done) {
          view.shareButton_clickHandler(event).then(function() {
            csv = JSON.stringify(csv, null, '\t');
            view.writeCordovaFile.calledWith(cordova.file.cacheDirectory, 'export.csv', csv).should.be.true();
          }).then(done);
        });

        it('should call window.plugins.socialsharing.shareWithOptions', function(done) {
          view.shareButton_clickHandler(event).then(function() {
           window.plugins.socialsharing.shareWithOptions.called.should.be.true();
          }).then(done);
        });

        it('should call window.plugins.socialsharing.shareWithOptions with correct options', function(done) {
          var options = {
            message: 'Encryptr csv with entries data',
            files: [cordova.file.cacheDirectory + filePath],
            subject: 'Encryptr data'
          };
          view.shareButton_clickHandler(event).then(function() {
            window.plugins.socialsharing.shareWithOptions.calledWith(options).should.be.true();
          }).then(done);
        });

      });
    
    });

    describe('Methods for NW.js plataforms', function() {
    
      describe('exportButton_clickHandler', function() {
        var event;

        beforeEach(function() {
          event = {
            stopPropagation: sinon.spy(),
            stopImmediatePropagation: sinon.spy(),
          };
          sinon.stub(view, 'getCsv', promise_function(csv));
          sinon.stub(view, 'saveCsv', promise_function(csv));
        });

        it('should have exportButton_clickHandler method', function() {
          view.exportButton_clickHandler.should.be.an('function');
        });

        it('should call event.stopPropagation', function() {
          view.exportButton_clickHandler(event);
          event.stopPropagation.called.should.be.true();
        });

        it('should call event.stopImmediatePropagation', function() {
          view.exportButton_clickHandler(event);
          event.stopImmediatePropagation.called.should.be.true();
        });

        it('should call getCsv', function() {
          view.exportButton_clickHandler(event);
          view.getCsv.called.should.be.true();
        });

        it('should call saveCsv', function(done) {
          view.exportButton_clickHandler(event).then(function() {
            view.saveCsv.called.should.be.true();
          }).then(done);
        });

        it('should call saveCsv with correct params', function(done) {
          view.exportButton_clickHandler(event).then(function() {
            view.saveCsv.calledWith(csv).should.be.true();
          }).then(done);
        });
      });

      describe('saveCsv', function() {

        var BlobNotStub, blob, url, a_object, type;

        beforeEach(function() {
          type = 'text/csv';
          url = 'http://loclahost:3000/4901-234-234-653-2134';
          URL = {
            createObjectURL: sinon.stub().returns(url)
          };
          a_object = sinon.stub().returns('<a></a>');
          a_object.click = sinon.spy();
          sinon.stub(document, 'createElement').returns(a_object);
          BlobNotStub = JSON.parse(JSON.stringify(Blob));
          blob = 'blob';
          Blob = sinon.stub().returns(blob);
          sinon.stub(document.body, 'appendChild');
          sinon.stub(document.body, 'removeChild');
          window.URL = {
            revokeObjectURL: sinon.spy(),
            createObjectURL: sinon.stub().returns(url)
          };
        });

        afterEach(function() {
          Blob = BlobNotStub;
          document.body.appendChild.restore();
          document.body.removeChild.restore();
          document.createElement.restore();
        });

        it('should have saveCsv method', function() {
          view.saveCsv.should.be.an('function');
        });

        it('should call Blob', function() {
          view.saveCsv(csv);
          Blob.called.should.be.true();
        });

        it('should call Blob with correct params', function() {
          view.saveCsv(csv);
          Blob.calledWith([csv], {'type': type}).should.be.true();
        });

        it('should call document.createElement', function() {
          view.saveCsv(csv);
          document.createElement.called.should.be.true();
        });

        it('should call document.createElement with correct params', function() {
          view.saveCsv(csv);
          document.createElement.calledWith("a").should.be.true();
        });

        it('should call window.URL.createObjectURL', function() {
          view.saveCsv(csv);
          Blob.called.should.be.true();
        });

        it('should call document.body.appendChild', function() {
          view.saveCsv(csv);
          document.body.appendChild.called.should.be.true();
        });

        it('should call document.body.appendChild with correct params', function() {
          view.saveCsv(csv);
          document.body.appendChild.calledWith(a_object).should.be.true();
        });

        it('should call document.body.removeChild', function() {
          view.saveCsv(csv);
          document.body.removeChild.called.should.be.true();
        });

        it('should call document.body.removeChild with correct params', function() {
          view.saveCsv(csv);
          document.body.removeChild.calledWith(a_object).should.be.true();
        });

        it('should call window.URL.revokeObjectURL', function() {
          view.saveCsv(csv);
          window.URL.revokeObjectURL.called.should.be.true();
        });

        it('should call window.URL.revokeObjectURL with correct params', function() {
          view.saveCsv(csv);
          window.URL.revokeObjectURL.calledWith(url).should.be.true();
        });

        it('should call a.click', function() {
          view.saveCsv(csv);
          a_object.click.called.should.be.true();
        });

      });
    
    }); 

});
