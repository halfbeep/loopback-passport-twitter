// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-example-passport
// This file is licensed under the MIT License.
// License text available at https://opensour/authce.org/licenses/MIT
'use strict';
var loopback = require('loopback');
var boot = require('loopback-boot');
var app = module.exports = loopback();
var cookieParser = require('cookie-parser');
var session = require('express-session');
var hmacsha1 = require('hmacsha1');

// Passport configurators..
var loopbackPassport = require('loopback-component-passport');
var PassportConfigurator = loopbackPassport.PassportConfigurator;
var passportConfigurator = new PassportConfigurator(app);

// Shaun 3 July 2018
// added http modules to get Tweets
const OAuth = require('oauth');
const http = require('http')
const https = require('https')

let this_oauth_token = 'blank_auth_toke'
let this_oauth_verifier = 'blank_auth_verifier'
let responseStr = 'Completed Request - [AUTHORISED TWEETS to SHOW HERE]';

/*
 * body-parser is a piece of express middleware that
 *   reads a form's input and stores it as a javascript
 *   object accessible through `req.body`
 *
 */
var bodyParser = require('body-parser');

/**
 * Flash messages for passport
 *
 * Setting the failureFlash option to true instructs Passport to flash an
 * error message using the message given by the strategy's verify callback,
 * if any. This is often the best approach, because the verify callback
 * can make the most accurate determination of why authentication failed.
 */
var flash      = require('express-flash');

// attempt to build the providers/passport config
var config = {};
try {
  config = require('../providers.json');
} catch (err) {
  console.trace(err);
  process.exit(1); // fatal
}

// -- Add your pre-processing middleware here --
/*
app.use(loopback.token({
    model: app.models.accessToken
}));
*/

// Setup the view engine (jade)
var path = require('path');
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// boot scripts mount components like REST API
boot(app, __dirname);

// to support JSON-encoded bodies
app.middleware('parse', bodyParser.json());
// to support URL-encoded bodies
app.middleware('parse', bodyParser.urlencoded({
  extended: true,
}));

// The access token is only available after boot
app.middleware('auth', loopback.token({
  model: app.models.accessToken,
}));

app.middleware('session:before', cookieParser(app.get('cookieSecret')));
app.middleware('session', session({
  secret: 'kitty',
  saveUninitialized: true,
  resave: true,
}));
passportConfigurator.init();

// We need flash messages to see passport errors
app.use(flash());

passportConfigurator.setupModels({
  userModel: app.models.user,
  userIdentityModel: app.models.userIdentity,
  userCredentialModel: app.models.userCredential,
});
for (var s in config) {
  var c = config[s];
  c.session = c.session !== false;
  passportConfigurator.configureProvider(s, c);
}
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

app.get('/', function(req, res, next) {
  res.render('pages/index', {user:
    req.user,
    url: req.url,
  });
});

app.get('/privacy', function(req, res, next) {
  res.render('pages/privacyPolicy', {user:
    req.user,
    url: req.url,
  });
});

// handle call back
// never manged to this working
// so I binned it
app.get('/ath/twitter/cb', function(req, res) {

    console.log('req.query.oauth_token')
    console.log(req.query.oauth_token)

    console.log('req.query.oauth_verifier')
    console.log(req.query.oauth_verifier)

    this_req.query.oauth_token = req.query.oauth_token;
    this_oauth_verifier = req.query.oauth_verifier;

    res.send('Twitter Called Back');

});


var checkForTweets = new Promise(function(resolve, reject) {
    resolve('Success!');
    reject('Failed');
});


async function getTweets(locAuth, locId) {
    try {
        await locAuth.get(
            'https://api.twitter.com/1.1/search/tweets.json?q=' + locId,
            '1013516560286265345-m49rWxpkOAe67YNLL9CeLVEXlQYOPB', // user token for this app
            'F2GBSZNQ7ErekyJMwlaPGVNzXarbkOL8zSVNdcKUXz3VT', // user secret for this app
            function (e, data, res){
                if (e) console.error(e);
                console.log('ASYN sync call here');
                console.log(JSON.stringify(require('util').inspect(data)));
            });
    } catch (e) {
        console.error(e); // 💩
    }
};

app.get('/tweets', ensureLoggedIn('/login'), function(req, res) {

    var start = Date.now();

    var user_id = req.query.id;

    var thisOAuth = new OAuth.OAuth(
        'https://api.twitter.com/oauth/request_token',
        'https://api.twitter.com/oauth/access_token',
        'eFmyCHQVhC5atiLAis6tStTkD',  // your APPS consumer API key
        'h5WaGdejXcW0woOZSnot8q07liBRKcqE8cnJeCO22voGYLUNsw', // your APPS Twitter application secret'
        '1.0A',
        null,
        'HMAC-SHA1'
    );

    getTweets(thisOAuth, user_id);

    thisOAuth.get(
        'https://api.twitter.com/1.1/search/tweets.json?q=' + user_id,
        // 'https://api.twitter.com/1.1/trends/place.json?id=23424977',  // trends
        '1013516560286265345-m49rWxpkOAe67YNLL9CeLVEXlQYOPB', // user token for this app
        'F2GBSZNQ7ErekyJMwlaPGVNzXarbkOL8zSVNdcKUXz3VT', // user secret for this app
        function (e, data, res){
            if (e) console.error(e);
            // responseStr = JSON.stringify(require('util').inspect(data));
            console.log('sync call here');
            console.log(require('util').inspect(data));
        });

    checkForTweets
        .then(function(value) {
        console.log(value);
        // expected output: "Success!"
    });

    res.send(responseStr);

});


// not used !
function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
            .toString(16)
            .substring(1);
    }
    return s4() + s4() + 'x' + s4() + 'x' + s4() + 'x' + s4() + 'x' + s4() + s4() + s4();
}


app.get('/auth/account', ensureLoggedIn('/login'), function(req, res, next) {
  res.render('pages/loginProfiles', {
    user: req.user,
    url: req.url,
  });
});

app.get('/local', function(req, res, next) {
  res.render('pages/local', {
    user: req.user,
    url: req.url,
  });
});

app.get('/ldap', function(req, res, next) {
  res.render('pages/ldap', {
    user: req.user,
    url: req.url,
  });
});

app.get('/signup', function(req, res, next) {
  res.render('pages/signup', {
    user: req.user,
    url: req.url,
  });
});

app.post('/signup', function(req, res, next) {
  var User = app.models.user;

  var newUser = {};
  newUser.email = req.body.email.toLowerCase();
  newUser.username = req.body.username.trim();
  newUser.password = req.body.password;

  User.create(newUser, function(err, user) {
    if (err) {
      req.flash('error', err.message);
      return res.redirect('back');
    } else {
      // Passport exposes a login() function on req (also aliased as logIn())
      // that can be used to establish a login session. This function is
      // primarily used when users sign up, during which req.login() can
      // be invoked to log in the newly registered user.
      req.login(user, function(err) {
        if (err) {
          req.flash('error', err.message);
          return res.redirect('back');
        }
        return res.redirect('/auth/account');
      });
    }
  });
});

app.get('/login', function(req, res, next) {
  res.render('pages/login', {
    user: req.user,
    url: req.url,
  });
});

app.get('/auth/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

app.start = function() {
  // start the web server
  return app.listen(function() {
    app.emit('started');
    var baseUrl = app.get('url').replace(/\/$/, '');
    console.log('web server listening at: %s', baseUrl);
    if (app.get('loopback-component-explorer')) {
      var explorerPath = app.get('loopback-component-explorer').mountPath;
      console.log('browse your REST API at %s%s', baseUrl, explorerPath);
    }
  });
};

// start the server if `$ node server.js`
if (require.main === module) {
  app.start();
}
