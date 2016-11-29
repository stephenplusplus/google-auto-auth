'use strict';

var assert = require('assert');
var assign = require('object-assign');
var googleAuthLibrary = require('google-auth-library');
var mockery = require('mockery');

var googleAuthLibraryOverride;
function fakeGoogleAuthLibrary() {
  return (googleAuthLibraryOverride || googleAuthLibrary)
    .apply(null, arguments);
}

var requestOverride;
function fakeRequest() {
  return (requestOverride || function () {}).apply(null, arguments);
}

describe('googleAutoAuth', function () {
  var googleAutoAuth;
  var auth;

  before(function () {
    mockery.registerMock('google-auth-library', fakeGoogleAuthLibrary);
    mockery.registerMock('request', fakeRequest);

    mockery.enable({
      useCleanCache: true,
      warnOnUnregistered: false
    });

    googleAutoAuth = require('./index.js');
  });

  after(function () {
    mockery.deregisterAll();
    mockery.disable();
  });

  beforeEach(function () {
    requestOverride = null;
    googleAuthLibraryOverride = null;
    auth = googleAutoAuth();
  });

  describe('authorizeRequest', function () {
    it('should get a token', function (done) {
      auth.getToken = function () {
        done();
      };

      auth.authorizeRequest({}, assert.ifError);
    });

    it('should execute callback with error', function (done) {
      var error = new Error('Error.');

      auth.getToken = function (callback) {
        callback(error);
      };

      auth.authorizeRequest({}, function (err) {
        assert.strictEqual(err, error);
        done();
      });
    });

    it('should extend the request options with token', function (done) {
      var token = 'abctoken';

      var reqOpts = {
        uri: 'a',
        headers: {
          a: 'b',
          c: 'd'
        }
      };

      var expectedAuthorizedReqOpts = assign({}, reqOpts);
      expectedAuthorizedReqOpts.headers = assign(reqOpts.headers, {
        Authorization: 'Bearer ' + token
      });

      auth.getToken = function (callback) {
        callback(null, token);
      };

      auth.authorizeRequest(reqOpts, function (err, authorizedReqOpts) {
        assert.ifError(err);
        assert.deepEqual(authorizedReqOpts, expectedAuthorizedReqOpts);
        done();
      });
    });
  });

  describe('getAuthClient', function () {
    beforeEach(function() {
      process.chdir(__dirname);
    });

    it('should re-use an existing authClient', function (done) {
      auth.authClient = { a: 'b', c: 'd' };

      auth.getAuthClient(function (err, authClient) {
        assert.strictEqual(authClient, auth.authClient);
        done();
      });
    });

    it('should use google-auth-library', function () {
      var googleAuthLibraryCalled = false;

      googleAuthLibraryOverride = function () {
        googleAuthLibraryCalled = true;
        return {
          getApplicationDefault: function () {}
        };
      };

      auth.getAuthClient(assert.ifError);
      assert.strictEqual(googleAuthLibraryCalled, true);
    });

    it('should create a google auth client from JSON', function (done) {
      auth.config = {
        keyFile: '../test.keyfile.json',
        scopes: ['dev.scope']
      };

      var expectedJson = require('./test.keyfile.json');

      var googleAuthClient = {
        createScopedRequired: function () {}
      };
      var projectId = 'project-id';

      googleAuthLibraryOverride = function () {
        return {
          fromJSON: function (json, callback) {
            assert.deepEqual(json, expectedJson);

            callback(null, googleAuthClient, projectId);
          }
        };
      };

      // to test that `path.resolve` is being used
      process.chdir('node_modules');

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(authClient.scopes, auth.config.scopes);
        assert.strictEqual(auth.projectId, projectId);

        assert.strictEqual(auth.authClient, googleAuthClient);
        assert.strictEqual(authClient, googleAuthClient);

        done();
      });
    });

    it('should create an auth client from credentials', function (done) {
      var googleAuthClient = {
        createScopedRequired: function () {}
      };
      var projectId = 'project-id';

      googleAuthLibraryOverride = function () {
        return {
          fromJSON: function (json, callback) {
            assert.deepEqual(json, auth.config.credentials);

            callback(null, googleAuthClient, projectId);
          }
        };
      };

      auth.config = {
        credentials: { a: 'b', c: 'd' }
      };

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(auth.projectId, projectId);

        assert.strictEqual(auth.authClient, googleAuthClient);
        assert.strictEqual(authClient, googleAuthClient);

        done();
      });
    });

    it('should create a JWT auth client from non-JSON', function (done) {
      var jwt = {
        createScopedRequired: function () {}
      };

      googleAuthLibraryOverride = function () {
        return {
          JWT: function () { return jwt; }
        };
      };

      auth.config = {
        keyFilename: 'key.p12',
        email: 'example@example.com',
        scopes: ['dev.scope']
      };

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(jwt.keyFile, auth.config.keyFilename);
        assert.strictEqual(jwt.email, auth.config.email);
        assert.strictEqual(jwt.scopes, auth.config.scopes);

        assert.strictEqual(auth.authClient, jwt);
        assert.strictEqual(authClient, jwt);

        done();
      });
    });

    it('should create an auth client from magic', function (done) {
      var googleAuthClient = {
        createScopedRequired: function () {}
      };

      googleAuthLibraryOverride = function () {
        return {
          getApplicationDefault: function (callback) {
            callback(null, googleAuthClient);
          }
        };
      };

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(auth.authClient, googleAuthClient);
        assert.strictEqual(authClient, googleAuthClient);

        done();
      });
    });

    it('should return scope error if necessary', function (done) {
      auth.config = {
        scopes: []
      };

      var fakeAuthClient = {
        createScopedRequired: function () {
          return true;
        }
      };

      googleAuthLibraryOverride = function () {
        return {
          getApplicationDefault: function (callback) {
            callback(null, fakeAuthClient);
          }
        };
      };

      auth.getAuthClient(function (e) {
        assert.strictEqual(e.code, 'MISSING_SCOPE');
        assert.strictEqual(e.message, 'Scopes are required for this request.');
        done();
      });
    });

    it('should pass back any errors from the authClient', function (done) {
      var error = new Error('Error.');

      googleAuthLibraryOverride = function () {
        return {
          getApplicationDefault: function (callback) {
            callback(error);
          }
        };
      };

      auth.getAuthClient(function (err) {
        assert.strictEqual(err,error);
        done();
      });
    });
  });

  describe('getCredentials', function () {
    it('should get an auth client', function (done) {
      auth.getAuthClient = function () {
        done();
      };

      auth.getCredentials(assert.ifError);
    });

    it('should execute callback with error', function (done) {
      var error = new Error('Error.');

      auth.getAuthClient = function (callback) {
        callback(error);
      };

      auth.getCredentials(function (err) {
        assert.strictEqual(err, error);
        done();
      });
    });

    it('should execute callback with object', function (done) {
      var credentials = { email: 'email', key: 'key' };

      auth.getAuthClient = function (callback) {
        callback(null, credentials);
      };

      auth.getCredentials(function (err, creds) {
        assert.ifError(err);

        assert.strictEqual(creds.client_email, credentials.email);
        assert.strictEqual(creds.private_key, credentials.key);

        done();
      });
    });

    it('should return error if authorize is not available', function (done) {
      auth.getAuthClient = function (callback) {
        callback(null, {});
      };

      auth.getCredentials(function (err) {
        assert.strictEqual(err.message, 'Could not get credentials without a JSON, pem, or p12 keyfile.');
        done();
      });
    });

    it('should authorize if necessary', function (done) {
      auth.getAuthClient = function (callback) {
        callback(null, {
          authorize: function () {
            done();
          }
        });
      };

      auth.getCredentials(assert.ifError);
    });

    it('should execute callback with error from auth', function (done) {
      var error = new Error('Error.');

      auth.getAuthClient = function (callback) {
        callback(null, {
          authorize: function (callback) {
            callback(error);
          }
        });
      };

      auth.getCredentials(function (err) {
        assert.strictEqual(err, error);
        done();
      });
    });

    it('should call getCredentials again', function (done) {
      auth.getAuthClient = function (callback) {
        callback(null, {
          authorize: function (callback) {
            auth.getCredentials = function () {
              done();
            };

            callback();
          }
        });
      };

      auth.getCredentials(assert.ifError);
    });
  });

  describe('getEnvironment', function () {
    it('should call all environment detection methods', function (done) {
      auth.isAppEngine = function (callback) {
        callback();
      };

      auth.isCloudFunction = function (callback) {
        callback();
      };

      auth.isComputeEngine = function (callback) {
        callback();
      };

      auth.getEnvironment(function (err, environment) {
        assert.ifError(err);
        assert.strictEqual(environment, auth.environment);
        done();
      });
    });
  });

  describe('getProjectId', function () {
    var PROJECT_ID = 'project-id';

    it('should return a project ID if already set', function (done) {
      auth.getAuthClient = function () {
        done(); // Will cause the test to blow up
      };

      auth.projectId = PROJECT_ID;

      auth.getProjectId(function (err, projectId) {
        assert.ifError(err);
        assert.strictEqual(projectId, PROJECT_ID);
        done();
      });
    });

    it('should get an auth client', function (done) {
      auth.getAuthClient = function () {
        done();
      };

      auth.getProjectId(assert.ifError);
    });

    it('should execute callback with error', function (done) {
      var error = new Error('Error.');

      auth.getAuthClient = function (callback) {
        callback(error);
      };

      auth.getProjectId(function (err) {
        assert.strictEqual(err, error);
        done();
      });
    });

    it('should get a project ID', function (done) {
      auth.getAuthClient = function (callback) {
        auth.projectId = PROJECT_ID;
        callback();
      };

      auth.getProjectId(function (err, projectId) {
        assert.ifError(err);
        assert.strictEqual(projectId, PROJECT_ID);
        done();
      });
    });
  });

  describe('getToken', function () {
    it('should get an auth client', function (done) {
      auth.getAuthClient = function () {
        done();
      };

      auth.getToken(assert.ifError);
    });

    it('should execute callback with error', function (done) {
      var error = new Error('Error.');

      auth.getAuthClient = function (callback) {
        callback(error);
      };

      auth.getToken(function (err) {
        assert.strictEqual(err, error);
        done();
      });
    });

    it('should get an access token', function (done) {
      var fakeClient = {
        getAccessToken: function (callback) {
          callback();
        }
      };

      auth.getAuthClient = function (callback) {
        callback(null, fakeClient);
      };

      auth.getToken(done);
    });
  });

  describe('isAppEngine', function () {
    var ENV_VARS = [
      'GAE_SERVICE',
      'GAE_MODULE_NAME'
    ];

    afterEach(function () {
      ENV_VARS.forEach(function (envVarName) {
        delete process.env[envVarName];
      });
    });

    it('should return false without env vars sets', function (done) {
      auth.isAppEngine(function (err, isAppEngine) {
        assert.ifError(err);
        assert.strictEqual(isAppEngine, false);
        done();
      });
    });

    it('should detect GAE_SERVICE', function (done) {
      process.env.GAE_SERVICE = 'service-name';

      assert.strictEqual(auth.environment.IS_APP_ENGINE, undefined);

      auth.isAppEngine(function (err, isAppEngine) {
        assert.ifError(err);
        assert.strictEqual(auth.environment.IS_APP_ENGINE, true);
        assert.strictEqual(isAppEngine, true);
        done();
      });
    });

    it('should detect GAE_MODULE_NAME', function (done) {
      process.env.GAE_MODULE_NAME = 'module-name';

      assert.strictEqual(auth.environment.IS_APP_ENGINE, undefined);

      auth.isAppEngine(function (err, isAppEngine) {
        assert.ifError(err);
        assert.strictEqual(auth.environment.IS_APP_ENGINE, true);
        assert.strictEqual(isAppEngine, true);
        done();
      });
    });
  });

  describe('isCloudFunction', function () {
    var ENV_VARS = [
      'FUNCTION_NAME'
    ];

    afterEach(function () {
      ENV_VARS.forEach(function (envVarName) {
        delete process.env[envVarName];
      });
    });

    it('should return false without env vars sets', function (done) {
      auth.isCloudFunction(function (err, isCloudFunction) {
        assert.ifError(err);
        assert.strictEqual(isCloudFunction, false);
        done();
      });
    });

    it('should detect FUNCTION_NAME', function (done) {
      process.env.FUNCTION_NAME = 'function-name';

      assert.strictEqual(auth.environment.IS_CLOUD_FUNCTION, undefined);

      auth.isCloudFunction(function (err, isCloudFunction) {
        assert.ifError(err);
        assert.strictEqual(auth.environment.IS_CLOUD_FUNCTION, true);
        assert.strictEqual(isCloudFunction, true);
        done();
      });
    });
  });

  describe('isComputeEngine', function () {
    it('should return an existing value', function (done) {
      requestOverride = done; // will make test fail if called

      auth.environment.IS_COMPUTE_ENGINE = 'test';

      auth.isComputeEngine(function (err, isComputeEngine) {
        assert.ifError(err);
        assert.strictEqual(isComputeEngine, 'test');
        done();
      });
    });

    it('should make the correct request', function (done) {
      requestOverride = function (uri) {
        assert.strictEqual(uri, 'http://metadata.google.internal');
        done();
      };

      auth.isComputeEngine(assert.ifError);
    });

    it('should set false if request errors', function (done) {
      requestOverride = function (uri, callback) {
        callback(new Error(':('));
      };

      assert.strictEqual(auth.environment.IS_COMPUTE_ENGINE, undefined);

      auth.isComputeEngine(function (err, isComputeEngine) {
        assert.ifError(err);
        assert.strictEqual(auth.environment.IS_COMPUTE_ENGINE, false);
        assert.strictEqual(isComputeEngine, false);
        done();
      });
    });

    it('should set true if header matches', function (done) {
      requestOverride = function (uri, callback) {
        callback(null, {
          headers: {
            'metadata-flavor': 'Google'
          }
        });
      };

      assert.strictEqual(auth.environment.IS_COMPUTE_ENGINE, undefined);

      auth.isComputeEngine(function (err, isComputeEngine) {
        assert.ifError(err);
        assert.strictEqual(auth.environment.IS_COMPUTE_ENGINE, true);
        assert.strictEqual(isComputeEngine, true);
        done();
      });
    });
  });
});