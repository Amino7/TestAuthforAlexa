//npm modules
const express = require('express');
const uuid = require('uuid/v4')
const session = require('express-session')
const FileStore = require('session-file-store')(session);
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const axios = require('axios');
const bcrypt = require('bcrypt-nodejs');
const https = require('https');
const http = require('http');
const fs = require('fs');
const helmet = require('helmet');
const FacebookStrategy = require('passport-facebook').Strategy;
const configAuth = require('./config/auth.js');
const csrf = require('csurf');
const RateLimit = require('express-rate-limit');



passport.use(new FacebookStrategy({
        // pull in our app id and secret from our auth.js file
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL
    },

    // facebook will send back the token and profile
    function(token, refreshToken, profile, done) {
          console.log("Token: " + token);
          console.log("refreshToken: " + refreshToken);
          console.log("Profile: " + JSON.stringify(profile));
          // find or create user
          axios.get(`http://localhost:5000/users?id=${profile.id}`)
          .then(res => {
            const user = res.data[0]
            console.log(res.data);
            if (!user) {
              console.log("creating new user ...")
              axios.post('http://localhost:5000/users/', profile._json);
            }
          })
          .catch(error => done(error));

          return done(null, profile._json);

}));

// configure passport.js to use the local strategy
passport.use(new LocalStrategy(
  { usernameField: 'username' },
  (username, password, done) => {
    axios.get(`http://localhost:5000/users?username=${username}`)
    .then(res => {
      const user = res.data[0];
      if (!user) {
        return done(null, false, { message: 'Invalid credentials.\n' });
      }
      if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false, { message: 'Invalid credentials.\n' });
      }
      console.log("Found User: "+ res.data[0].username);
      return done(null, user);
    })
    .catch(error => done(error));
  }
));

// tell passport how to serialize the user
// saves user.id in session
passport.serializeUser((user, done) => {
  done(null, user.id);
});
// gets the user from id in the session
passport.deserializeUser((id, done) => {
  axios.get(`http://localhost:5000/users/${id}`)
  .then(res => done(null, res.data) )
  .catch(error => done(error, false))
});

const options = {
  key: fs.readFileSync('./encryption/ddc4kiot.key'),
  cert: fs.readFileSync('./encryption/ddc4kiot.crt')
};

// create the server
const app = express();

// add & configure middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(session({
  genid: (req) => {
    return uuid() // use UUIDs for session IDs
  },                   // TODO: ttl macht nichts?
  store: new FileStore({ttl: 20,
                        path: "./sessions",
                        reapInterval: 30
                        }),
  // später natürlich auslagern
  secret: 'keyboard cat',
  //hier evtl false besser, check doku
  resave: true,
  saveUninitialized: false,
  name: 'id',
  unset: 'destroy', // when someone explicitly deletes the session, destroy it
  cookie: {
    // ohne zeitbegrenzung wird cookie beim beenden der
    // browsersitzung gelöscht -aber funzt nicht so gut
    // evtl für Internet Explorer zusätzlich expires setzen
    maxAge: 1000  * 60 * 5,
    httpOnly: true,
    secure: true
  },

}))
app.use(passport.initialize());
app.use(passport.session());
app.use(csrf());

const apiLimiter = new RateLimit({
  windowMs: 15*60*1000, // 15 minutes
  max: 100,
  delayMs: 0 // disabled
});
app.use('/', apiLimiter);

const createAccountLimiter = new RateLimit({
  windowMs: 60*60*1000, // 1 hour window
  delayAfter: 1, // begin slowing down responses after the first request
  delayMs: 3*1000, // slow down subsequent responses by 3 seconds per request
  max: 5, // start blocking after 5 requests
  message: "Too many requests from this IP, please try again after an hour"
});

app.use( function( req, res, next ) {
  res.locals.csrftoken = req.csrfToken() ;
  next();
} ) ;

app

// create the homepage route at '/', it has a form post to test against csfr
app.get('/', (req, res) => {
  res.send(`
    <h1>Hello World</h1>
    <form action="/entry" method="POST">
      <div>
        <label for="message">Enter a message</label>
        <input id="message" name="message" type="text" />
      </div>
      <input type="submit" value="Submit" />
      <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
    </form>
    <br>
    <form action="/login" method="POST">
      <div>
        <label for="username">Username:</label>
        <input id="username" name="username" type="text" />
        <br>
        <label for="password">Password:</label>
        <input id="password" name="password" type="text" />
      </div>
      <input type="submit" value="Submit" />
      <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
    </form>
    <br>
    <a href="/auth/facebook">Login with Facebook</a><br>
    <a href="/auth/google">Login with Google</a><br>
  `);
});

app.post('/entry',createAccountLimiter, (req, res) => {
  console.log(`Message received: ${req.body.message}`);
  res.send(`CSRF token used: ${req.body._csrf}, Message received: ${req.body.message}`);
});

// create the login get and post routes
app.get('/login', (req, res) => {
  res.send(`You got the login page!\n`)
})

app.get('/facebook', (req,res) =>{
    res.send('<a href="/auth/facebook">Login with Facebook</a><br>'+
             '<a href="/auth/google">Login with Google</a><br>');
})

// Redirect the user to Facebook for authentication.  When complete,
// Facebook will redirect the user back to the application at
//     /auth/facebook/callback
app.get('/auth/facebook', passport.authenticate('facebook'));

// Facebook will redirect the user to this URL after approval.  Finish the
// authentication process by attempting to obtain an access token.  If
// access was granted, the user will be logged in.  Otherwise,
// authentication has failed.
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { successRedirect: '/testcallback',
                                      failureRedirect: '/' }));
app.get('/testcallback', (req,res) =>{
    res.send('You have been succesfully redirected from facebook.'+
              '<br><a href="/authrequired">check if you are logged in</a>');
})

app.get('/auth/google', (req,res) =>{
    res.send('kommt noch...');
})


app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if(info) {return res.send(info.message)}
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login'); }
    req.login(user, (err) => {
      if (err) { return next(err); }
      return res.redirect('/authrequired');
    })
  })(req, res, next);
})

app.get('/authrequired', (req, res) => {
  if(req.isAuthenticated()) {
    res.send('you hit the authentication endpoint\n'+
             '<br><a href="/authrequired">check if you are logged in</a>'+
             '<br><a href="/destroy">log out</a>');

  } else {
    res.redirect('/')
  }
})

app.get('/destroy', function (req, res) {
  req.session.destroy(function(err) {
    if (err) {
      console.error(err);
    } else {
      res.clearCookie('id');
      res.send('you logged out!\n'+
               '<br><a href="/">back to homepage</a>');
    }
  });
});

app.get('/alexa',(req,res) =>{
  res.send('kommt noch...');
  console.log("alexa hat auf mich zugegriffen!")
})






// tell the server what port to listen on
http.createServer( app).listen(process.env.PORT,"0.0.0.0");
console.log('Listening on localhost:8080')

//TODO: test module safety with nsp&snyk
