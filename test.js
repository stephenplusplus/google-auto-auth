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

  describe('getToken', function () {
    it('should get an auth client', function (done) {
      auth._getClient = function () {
        done();
      };

      auth.getToken(assert.ifError);
    });

    it('should execute callback with error', function (done) {
      var error = new Error('Error.');

      auth._getClient = function (callback) {
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

      auth._getClient = function (callback) {
        callback(null, fakeClient);
      };

      auth.getToken(done);
    });
  });

  describe('_getClient', function () {
    it('should re-use an existing authClient', function (done) {
      auth.authClient = { a: 'b', c: 'd' };

      auth._getClient(function (err, authClient) {
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

      auth._getClient(assert.ifError);
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

      auth._getClient(function (err, authClient) {
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

      auth._getClient(function (err, authClient) {
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

      auth._getClient(function (err) {
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

      auth._getClient(done);
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

      auth._getClient(done);
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

      auth._getClient(function (err) {
        assert.strictEqual(err,error);
        done();
      });
    });
  });
});