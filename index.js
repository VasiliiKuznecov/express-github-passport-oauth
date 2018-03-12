const express = require('express');
const passport = require('passport');
const Strategy = require('passport-github').Strategy;

const path = require('path');
const hbs = require('hbs');

const githubStrategy = new Strategy(
    {
        clientID: 'a734c7ed99d89785000b',
        clientSecret: '527b750fff429479f56890b974be29cd4d0a7fdf',
        callbackURL: 'http://localhost:3000/login/return'
    },
    (accessToken, refreshToken, profile, cb) => cb(null, profile)
);

passport.use(githubStrategy);
passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((object, cb) => cb(null, object));

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.get(
    '/',
    (req, res) =>res.render('home', { user: req.user })
);

app.get(
    '/login',
    passport.authenticate('github')
);

app.get(
    '/login/return',
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => res.redirect('/')
);

app.get(
    '/logout',
    (req, res) => {
        req.logout();
        res.redirect('/');
    }
);

app.get(
    '/profile',
    require('connect-ensure-login').ensureLoggedIn(),
    (req, res) => res.render('profile', { user: req.user }));

app.listen(3000);
