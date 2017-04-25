'use strict';

var async = require('async');
var fs = require('fs');
var GoogleAuth = require('google-auth-library');
var gcpMetadata = require('gcp-metadata');
var path = require('path');
var request = require('request');

class Auth {
  constructor(config) {
    this.authClientPromise = null;
    this.authClient = null;
    this.config = config || {};
    this.environment = {};
  }

  authorizeRequest (reqOpts, callback) {
    this.getToken((err, token) => {
      if (err) {
        callback(err);
        return;
      }

      var authorizedReqOpts = Object.assign({}, reqOpts, {
        headers: Object.assign({}, reqOpts.headers, {
          Authorization: `Bearer ${token}`
        })
      });

      callback(null, authorizedReqOpts);
    });
  }

  getAuthClient (callback) {
    var createAuthClientPromise = (resolve, reject) => {
      var googleAuth = new GoogleAuth();

      var config = this.config;
      var keyFile = config.keyFilename || config.keyFile;

      var addScope = (err, authClient, projectId) => {
        if (err) {
          reject(err);
          return;
        }

        if (authClient.createScopedRequired && authClient.createScopedRequired()) {
          if (!config.scopes || config.scopes.length === 0) {
            var scopeError = new Error('Scopes are required for this request.');
            scopeError.code = 'MISSING_SCOPE';
            reject(scopeError);
            return;
          }
        }

        authClient.scopes = config.scopes;
        this.authClient = authClient;
        this.projectId = projectId || authClient.projectId;

        resolve(authClient);
      };

      if (config.credentials) {
        googleAuth.fromJSON(config.credentials, addScope);
      } else if (keyFile) {
        keyFile = path.resolve(process.cwd(), keyFile);

        fs.readFile(keyFile, (err, contents) => {
          if (err) {
            reject(err);
            return;
          }

          try {
            googleAuth.fromJSON(JSON.parse(contents), addScope);
          } catch(e) {
            var authClient = new googleAuth.JWT();
            authClient.keyFile = keyFile;
            authClient.email = config.email;
            addScope(null, authClient);
          }
        });
      } else {
        googleAuth.getApplicationDefault(addScope);
      }
    };

    if (!this.authClientPromise) {
      if (this.authClient) {
        this.authClientPromise = Promise.resolve(this.authClient);
      } else {
        this.authClientPromise = new Promise(createAuthClientPromise);
      }
    }

    this.authClientPromise.then(callback.bind(null, null)).catch(callback);
  }

  getCredentials (callback) {
    this.getAuthClient((err, client) => {
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

      client.authorize(err => {
        if (err) {
          callback(err);
          return;
        }

        this.getCredentials(callback);
      });
    });
  }

  getEnvironment (callback) {
    async.parallel([
      cb => this.isAppEngine(cb),
      cb => this.isCloudFunction(cb),
      cb => this.isComputeEngine(cb),
      cb => this.isContainerEngine(cb)
    ], () => {
      callback(null, this.environment);
    });
  }

  getProjectId (callback) {
    if (this.projectId) {
      setImmediate(() => {
        callback(null, this.projectId);
      });
      return;
    }

    this.getAuthClient(err => {
      if (err) {
        callback(err);
        return;
      }

      callback(null, this.projectId);
    });
  }

  getToken (callback) {
    this.getAuthClient((err, client) => {
      if (err) {
        callback(err);
        return;
      }

      client.getAccessToken(callback);
    });
  }

  isAppEngine (callback) {
    setImmediate(() => {
      var env = this.environment;

      if (typeof env.IS_APP_ENGINE === 'undefined') {
        env.IS_APP_ENGINE = !!(process.env.GAE_SERVICE || process.env.GAE_MODULE_NAME);
      }

      callback(null, env.IS_APP_ENGINE);
    });
  }

  isCloudFunction (callback) {
    setImmediate(() => {
      var env = this.environment;

      if (typeof env.IS_CLOUD_FUNCTION === 'undefined') {
        env.IS_CLOUD_FUNCTION = !!process.env.FUNCTION_NAME;
      }

      callback(null, env.IS_CLOUD_FUNCTION);
    });
  }

  isComputeEngine (callback) {
    var env = this.environment;

    if (typeof env.IS_COMPUTE_ENGINE !== 'undefined') {
      setImmediate(() => {
        callback(null, env.IS_COMPUTE_ENGINE);
      });
      return;
    }

    request('http://metadata.google.internal', (err, res) => {
      env.IS_COMPUTE_ENGINE = !err && res.headers['metadata-flavor'] === 'Google';

      callback(null, env.IS_COMPUTE_ENGINE);
    });
  }

  isContainerEngine (callback) {
    var env = this.environment;

    if (typeof env.IS_CONTAINER_ENGINE !== 'undefined') {
      setImmediate(() => {
        callback(null, env.IS_CONTAINER_ENGINE);
      });
      return;
    }

    gcpMetadata.instance('/attributes/cluster-name', err => {
      env.IS_CONTAINER_ENGINE = !err;

      callback(null, env.IS_CONTAINER_ENGINE);
    });
  }
}

module.exports = config => {
  return new Auth(config);
};
