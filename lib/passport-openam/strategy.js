/**
* Module dependencies.
*/
var passport = require('passport')
  , OpenAm = require('openam').OpenAm
	, querystring = require('querystring')
	, util = require('util')
	, utils = require('./utils')
	, url = require('url')
  , InternalOpenAmError = require('./errors/internalopenamerror');




/**
* `OpenAmStrategy` constructor.
*
* The OpenAm authentication strategy authenticates requests using the OAuth
* protocol.
*
* OAuth provides a facility for delegated authentication, whereby users can
* authenticate using a third-party service such as Twitter. Delegating in this
* manner involves a sequence of events, including redirecting the user to the
* third-party service for authorization. Once authorization has been obtained,
* the user is redirected back to the application and a token can be used to
* obtain credentials.
*
* Applications must supply a `verify` callback which accepts a `token`,
* `tokenSecret` and service-specific `profile`, and then calls the `done`
* callback supplying a `user`, which should be set to `false` if the
* credentials are not valid. If an exception occured, `err` should be set.
*
* Options:
* - `requestTokenURL` URL used to obtain an unauthorized request token
* - `accessTokenURL` URL used to exchange a user-authorized request token for an access token
* - `userAuthorizationURL` URL used to obtain user authorization
* - `consumerKey` identifies client to service provider
* - `consumerSecret` secret used to establish ownership of the consumer key
* - `callbackURL` URL to which the service provider will redirect the user after obtaining authorization
*
* Examples:
*
* passport.use(new OAuthStrategy({
* openAmBaseURL: 'https://www.example.com/openam/',
* consumerKey: '123-456-789',
* consumerSecret: 'shhh-its-a-secret'
* callbackURL: 'https://www.example.net/auth/example/callback'
* },
* function(token, tokenSecret, profile, done) {
* User.findOrCreate(..., function (err, user) {
* done(err, user);
* });
* }
* ));
*
* @param {Object} options
* @param {Function} verify
* @api public
*/



function OpenAmStrategy(options, verify) {
	options = options || {}
  passport.Strategy.call(this);
	this.name = 'openam';
  this._verify = verify;
	
	if (!options.openAmBaseUrl) throw new Error('OpenAmStrategy requires a openAmBaseUrl option');
  if (!options.callbackUrl) throw new Error('OpenAmStrategy requires a callbackUrl option');
	this._openAmRealm = (options.openAmRealm === undefined) ? "/" : options.openAmRealm;
	this._openAmCookieName = (options.openAmCookieName === undefined) ? "iPlanetDirectoryPro" : options.openAmCookieName;

	this._openam = new OpenAm(options.openAmBaseUrl, this._openAmRealm, this._openAmCookieName);

  this._callbackUrl = options.callbackUrl;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
  this._openAmLoginPage = (options.openAmLoginPage === undefined) ? true : options.openAmLoginPage;

}

/**
* Inherit from `passport.Strategy`.
*/
util.inherits(OpenAmStrategy, passport.Strategy);


/**
* Authenticate request by delegating to a service provider using OpenAM.
*
* @param {Object} req
* @api protected
*/
OpenAmStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OpenAM flows is encoded in the
    // query parameters, and should be propagated to the application.
    return this.fail();
  }

  var callbackUrl = options.callbackUrl || this._callbackUrl;
  if (callbackUrl) {
    var parsed = url.parse(callbackUrl);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }
  if (req.query && req.query.code) {
    var cookies = {};
    req.headers.cookie.split(';').forEach(function( cookie ) {
      var parts = cookie.split('=');
      cookies[ parts[ 0 ].trim() ] = ( parts[ 1 ] || '' ).trim();
    });
    if (cookies[this._openAmCookieName]) {
      var token = cookies[this._openAmCookieName]
      this._openam.isTokenValid(token, function(bool){
        if (bool) {
        self._loadUserProfile(token, function(err, profile){
          if (err) { return self.error(err); }
            self._verify(req, token, profile, function( err, user, info){
              if (err) { return self.error(err); }
              if(!user) { return self.fail(info); }
              self.success(user,info)
            });
        });
        } else {
           var params = {};
           params['goto'] = callbackUrl + "?code=true";
           var location = this._openam.getLoginUiUrl(params);
           this.redirect(location);
        }
      });
    }
   } else {
      var params = {};
      params['goto'] = callbackUrl + "?code=true";
      var location = this._openam.getLoginUiUrl(params);
      this.redirect(location);
  }
}

/**
* Load user profile, contingent upon options.
*
* @param {String} token
* @param {Function} done
* @api private
*/
OpenAmStrategy.prototype._loadUserProfile = function(token, done) {
  var self = this;
  
  function loadIt() {
    return self.userProfile(token, done);
  }
  function skipIt() {
    return done(null);
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(token, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
}

/**
* Retrieve user profile from service provider.
*
* @param {String} token
* @param {Function} done
* @api protected
*/
OpenAmStrategy.prototype.userProfile = function(token, done) {
  this._openam.getAttributes(token, function(err, data){
    if (err) { return done(new InternalOpenAmError('failed to get attributes', err)); }
    try {
      var profile = {};
      profile.id = data.tokenid;
      profile.username = data.uid;
      profile.displayName = data.cn;
      profile.name = {
                      familyName: data.sn,
                      givenName: data.givenname,
                    };
      profile.email = data.mail;
      profile._raw = data;
      done(null,profile);
    } catch(e){
      done(e);
    }
  });
}


/**
 * * Expose `OpenAmStrategy`.
 * */
module.exports = OpenAmStrategy;
