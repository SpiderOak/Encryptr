/*global module:false*/
module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    meta: {
      banner: '/*! <%= pkg.title || pkg.name %> - v<%= pkg.version %> - ' +
        '<%= grunt.template.today("yyyy-mm-dd") %>' + '\n' +
        '<%= pkg.homepage ? "* " + pkg.homepage : "" %>' + '\n' +
        ' * Copyright (c) <%= grunt.template.today("yyyy") %> <%= pkg.author %>;' + '\n' +
        ' * License: <%= _.pluck(pkg.licenses, "type").join(", ") %> (<%= _.pluck(pkg.licenses, "url").join(", ") %>)' + '\n' +
        ' */\n\n'
    },
    concat: {
      options: {
        banner:  '<%= meta.banner %>' + '// GENERATED FILE - DO NOT EDIT\n'
      },
      dist: {
        src: ['src/**/*.js'],
        dest: 'www/js/<%= pkg.name %>.js'
      },
      zepto: {
        src: [
          'components/zepto/src/zepto.js',
          'components/zepto/src/ajax.js',
          'components/zepto/src/assets.js',
          'components/zepto/src/data.js',
          'components/zepto/src/detect.js',
          'components/zepto/src/event.js',
          'components/zepto/src/form.js',
          'components/zepto/src/fx.js',
          'components/zepto/src/fx_methods.js',
          'components/zepto/src/gesture.js',
          'components/zepto/src/polyfill.js',
          'components/zepto/src/selector.js',
          'components/zepto/src/stack.js',
          'components/zepto/src/touch.js'
        ],
        dest: 'www/components/zepto/zepto.js'
      },
      underscore: {
        src: [
          'components/underscore/underscore.js'
        ],
        dest: 'www/components/underscore/underscore.js'
      },
      backbone: {
        src: [
          'components/backbone/backbone.js'
        ],
        dest: 'www/components/backbone/backbone.js'
      },
      backstack: {
        src: [
          'components/backstack/backstack.js'
        ],
        dest: 'www/components/backstack/backstack.js'
      },
      moment: {
        src: [
          'components/moment/moment.js'
        ],
        dest: 'www/components/moment/moment.js'
      },
      tests: {
        options: {
          banner: '<%= meta.banner %>'
        },
        src: [
          'tests/**/*.js'
        ],
        dest: 'www/tests/<%= pkg.name %>-tests.js'
      }
    },
    uglify: {
      dist: {
        src: [
          '<%= concat.dist.dest %>'
        ],
        dest: 'www/js/<%= pkg.name %>.min.js'
      },
      zepto: {
        src: [
          'www/components/zepto/zepto.js'
        ],
        dest: 'www/components/zepto/zepto.min.js'
      }
    },
    watch: {
      files: [
        '<%= jshint.files %>'
      ],
      tasks: ['jshint', 'concat', 'min']
    },
    shell: {
      _options: {
        failOnError: true,
        stdout: true
      },
      debug_ios: {
        command: 'cordova build ios && cordova emulate ios'
      },
      debug_android: {
        command: 'cordova build android && cordova emulate android'
      },
      debug_blackberry10: {
        command: 'cordova build blackberry10 && cordova emulate blackberry10'
      },
      // Some different reporters...
      mochaspec: {
        command:
          './node_modules/.bin/mocha-phantomjs www/tests/index.html',
        options: {
          failOnError: true,
          stdout: true
        }
      },
      mochamin: {
        command:
          './node_modules/.bin/mocha-phantomjs -R min www/tests/index.html',
        options: {
          failOnError: true,
          stdout: true
        }
      },
      mochadot: {
        command:
          './node_modules/.bin/mocha-phantomjs -R dot www/tests/index.html',
        options: {
          failOnError: true,
          stdout: true
        }
      },
      mochatap: {
        command:
          './node_modules/.bin/mocha-phantomjs -R tap www/tests/index.html',
        options: {
          failOnError: true,
          stdout: true
        }
      }
    },
    jshint: {
      files: ['Gruntfile.js', 'src/*.js', 'src/**/*.js'],
      options: {
        curly: true,
        eqeqeq: true,
        immed: true,
        latedef: true,
        newcap: true,
        noarg: true,
        sub: true,
        undef: true,
        boss: true,
        devel: true,
        eqnull: true,
        browser: true,
        globals: {
          cordova: true
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-shell');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-watch');
  
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  

  // Custom tasks
  grunt.registerTask('test', ['jshint', 'concat', 'min', 'shell:mochaspec']);
  grunt.registerTask('min', ['uglify']); // polyfil for uglify
  grunt.registerTask('debug','Create a debug build', function(platform) {
    grunt.task.run('jshint', 'concat', 'min', 'shell:mochadot');
    grunt.task.run('shell:debug_' + platform);
  });

  // Default task
  grunt.registerTask('default', ['jshint', 'concat', 'min', 'shell:mochaspec']);
  

};
