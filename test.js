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

describe('googleAutoAuth', function () {
  var googleAutoAuth;
  var auth;

  before(function () {
    mockery.registerMock('google-auth-library', fakeGoogleAuthLibrary);
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

    it('should create a JWT auth client from a keyFilename', function (done) {
      var jwt = {};

      googleAuthLibraryOverride = function () {
        return {
          JWT: function () { return jwt; }
        };
      };

      auth.config = {
        keyFilename: 'key.json',
        email: 'example@example.com',
        scopes: ['dev.scope']
      };

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(jwt.keyFile, auth.config.keyFilename);
        assert.strictEqual(jwt.email, auth.config.email);
        assert.strictEqual(jwt.scopes, auth.config.scopes);

        assert.strictEqual(authClient, jwt);

        done();
      });
    });

    it('should create a JWT auth client from a keyFile', function (done) {
      var jwt = {};

      googleAuthLibraryOverride = function () {
        return {
          JWT: function () { return jwt; }
        };
      };

      auth.config = {
        keyFile: 'key.json',
        email: 'example@example.com',
        scopes: ['dev.scope']
      };

      auth.getAuthClient(function (err, authClient) {
        assert.ifError(err);

        assert.strictEqual(jwt.keyFile, auth.config.keyFile);
        assert.strictEqual(jwt.email, auth.config.email);
        assert.strictEqual(jwt.scopes, auth.config.scopes);

        assert.strictEqual(authClient, jwt);

        done();
      });
    });

    it('should create an auth client from credentials', function (done) {
      var credentialsSet;

      googleAuthLibraryOverride = function () {
        return {
          fromJSON: function (credentials, callback) {
            credentialsSet = credentials;
            callback(null, {});
          }
        };
      };

      auth.config = {
        credentials: { a: 'b', c: 'd' }
      };

      auth.getAuthClient(function (err) {
        assert.ifError(err);
        assert.strictEqual(credentialsSet, auth.config.credentials);
        done();
      });
    });

    it('should create an auth client from magic', function (done) {
      googleAuthLibraryOverride = function () {
        return {
          getApplicationDefault: function (callback) {
            callback(null, {});
          }
        };
      };

      auth.getAuthClient(done);
    });

    it('should scope an auth client if necessary', function (done) {
      auth.config = {
        scopes: ['a.scope', 'b.scope']
      };

      var fakeAuthClient = {
        createScopedRequired: function () {
          return true;
        },
        createScoped: function (scopes) {
          assert.strictEqual(scopes, auth.config.scopes);
          return fakeAuthClient;
        },
        getAccessToken: function () {}
      };

      googleAuthLibraryOverride = function () {
        return {
          getApplicationDefault: function (callback) {
            callback(null, fakeAuthClient);
          }
        };
      };

      auth.getAuthClient(done);
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

    it('should return error if authorize is not available', function(done) {
      auth.getAuthClient = function (callback) {
        callback(null, {});
      };

      auth.getCredentials(function(err) {
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

    it('should immediately return an access token if one is configured', function(done) {
      auth.config = {
        accessToken: 'immediate_token'
      };

      auth.getToken(function(err, token) {
        assert.strictEqual(token, 'immediate_token');
        done();
      });
    });
  });
});
