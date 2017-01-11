'use strict';

var assign = require('object-assign');
var async = require('async');
var GoogleAuth = require('google-auth-library');
var path = require('path');
var request = require('request');

function Auth(config) {
  if (!(this instanceof Auth)) {
    return new Auth(config);
  }

  this.authClient = null;
  this.config = config || {};
  this.environment = {};
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
  var config = this.config;

  if (this.authClient) {
    setImmediate(function () {
      callback(null, self.authClient);
    });

    return;
  }

  var googleAuth = new GoogleAuth();
  var keyFile = config.keyFilename || config.keyFile;

  if (config.credentials || keyFile && path.extname(keyFile) === '.json') {
    var json = config.credentials;

    if (!json) {
      json = require(path.resolve(process.cwd(), keyFile));
    }

    googleAuth.fromJSON(json, addScope);
  } else if (keyFile) {
    var authClient = new googleAuth.JWT();
    authClient.keyFile = keyFile;
    authClient.email = config.email;
    addScope(null, authClient);
  } else if (config.apiKey) {
    googleAuth.fromAPIKey(config.apiKey, addScope);
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

Auth.prototype.getEnvironment = function (callback) {
  var self = this;

  async.parallel([
    this.isAppEngine.bind(this),
    this.isCloudFunction.bind(this),
    this.isComputeEngine.bind(this)
  ], function () {
    callback(null, self.environment);
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

Auth.prototype.isAppEngine = function (callback) {
  var self = this;

  setImmediate(function () {
    if (typeof self.environment.IS_APP_ENGINE === 'undefined') {
      self.environment.IS_APP_ENGINE =
        !!(process.env.GAE_SERVICE || process.env.GAE_MODULE_NAME);
    }

    callback(null, self.environment.IS_APP_ENGINE);
  });
};

Auth.prototype.isCloudFunction = function (callback) {
  var self = this;

  setImmediate(function () {
    if (typeof self.environment.IS_CLOUD_FUNCTION === 'undefined') {
      self.environment.IS_CLOUD_FUNCTION = !!process.env.FUNCTION_NAME;
    }

    callback(null, self.environment.IS_CLOUD_FUNCTION);
  });
};

Auth.prototype.isComputeEngine = function (callback) {
  var self = this;

  if (typeof this.environment.IS_COMPUTE_ENGINE !== 'undefined') {
    setImmediate(function () {
      callback(null, self.environment.IS_COMPUTE_ENGINE);
    });
    return;
  }

  request('http://metadata.google.internal', function (err, res) {
    self.environment.IS_COMPUTE_ENGINE =
      !err && res.headers['metadata-flavor'] === 'Google';

    callback(null, self.environment.IS_COMPUTE_ENGINE);
  });
};

module.exports = Auth;
