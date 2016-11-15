'use strict';

var assign = require('object-assign');
var GoogleAuth = require('google-auth-library');
var path = require('path');

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

Auth.prototype.getAuthClient = function (callback) {
  var self = this;
  var config = self.config;

  if (this.authClient) {
    setImmediate(function () {
      callback(null, self.authClient);
    });

    return;
  }

  var googleAuth = new GoogleAuth();
  var keyFile = config.keyFilename || config.keyFile;

  if (config.credentials || keyFile && path.extname(keyFile) === '.json') {
    googleAuth.fromJSON(config.credentials || require(keyFile), addScope);
  } else if (keyFile) {
    var authClient = new googleAuth.JWT();
    authClient.keyFile = keyFile;
    authClient.email = config.email;
    addScope(null, authClient);
  } else {
    googleAuth.getApplicationDefault(addScope);
  }

  function addScope(err, authClient, projectId) {
    if (err) {
      callback(err);
      return;
    }

    if (authClient.createScopedRequired && authClient.createScopedRequired()) {
      if (!config.scopes || config.scopes.length === 0) {
        var scopeError = new Error('Scopes are required for this request.');
        scopeError.code = 'MISSING_SCOPE';
        callback(scopeError);
        return;
      }
    }

    authClient.scopes = config.scopes;
    self.authClient = authClient;
    self.projectId = projectId || authClient.projectId;

    callback(null, authClient);
  }
};

Auth.prototype.getCredentials = function (callback) {
  var self = this;

  this.getAuthClient(function (err, client) {
    if (err) {
      callback(err);
      return;
    }

    if (client.email && client.key) {
      callback(null, {
        client_email: client.email,
        private_key: client.key
      });
      return;
    }

    if (!client.authorize) {
      callback(new Error('Could not get credentials without a JSON, pem, or p12 keyfile.'));
      return;
    }

    client.authorize(function (err) {
      if (err) {
        callback(err);
        return;
      }

      self.getCredentials(callback);
    });
  });
};

Auth.prototype.getProjectId = function (callback) {
  var self = this;

  if (this.projectId) {
    setImmediate(function () {
      callback(null, self.projectId);
    });

    return;
  }

  this.getAuthClient(function (err) {
    if (err) {
      callback(err);
      return;
    }

    callback(null, self.projectId);
  });
};

Auth.prototype.getToken = function (callback) {
  this.getAuthClient(function (err, client) {
    if (err) {
      callback(err);
      return;
    }

    client.getAccessToken(callback);
  });
};

module.exports = Auth;
