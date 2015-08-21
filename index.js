'use strict';

var assign = require('object-assign');
var GoogleAuth = require('google-auth-library');

function Auth(config) {
  if (!(this instanceof Auth)) {
    return new Auth(config);
  }

  this.authClient = null;
  this.config = config || {};
}

Auth.prototype.authorizeRequest = function (reqOpts, callback) {
  this.getToken(function (err, token) {
    if (err) {
      callback(err);
      return;
    }

    var authorizedReqOpts = assign({}, reqOpts);
    authorizedReqOpts.headers = authorizedReqOpts.headers || {};
    authorizedReqOpts.headers.Authorization = 'Bearer ' + token;

    callback(null, authorizedReqOpts);
  });
};

Auth.prototype.getToken = function (callback) {
  this._getClient(function (err, client) {
    if (err) {
      callback(err);
      return;
    }

    client.getAccessToken(callback);
  });
};

Auth.prototype._getClient = function (callback) {
  var self = this;
  var config = self.config;

  if (this.authClient) {
    setImmediate(function () {
      callback(null, self.authClient);
    });

    return;
  }

  var googleAuth = new GoogleAuth();

  if (config.keyFilename || config.keyFile) {
    var authClient = new googleAuth.JWT();
    authClient.keyFile = config.keyFilename || config.keyFile;
    authClient.email = config.email;
    authClient.scopes = config.scopes;
    addScope(null, authClient);
  } else if (config.credentials) {
    googleAuth.fromJSON(config.credentials, addScope);
  } else {
    googleAuth.getApplicationDefault(addScope);
  }

  function addScope(err, authClient) {
    if (err) {
      callback(err);
      return;
    }

    if (authClient.createScopedRequired && authClient.createScopedRequired()) {
      if (!config.scopes) {
        var scopeError = new Error('Scopes are required for this request.');
        scopeError.code = 'MISSING_SCOPE';
        callback(scopeError);
        return;
      }

      authClient = authClient.createScoped(config.scopes);
    }

    self.authClient = authClient;
    callback(null, authClient);
  }
};

module.exports = Auth;
