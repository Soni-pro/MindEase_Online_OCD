const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database(':memory:');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Create user table in SQLite database
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)");
});

// Passport configuration
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  db.get("SELECT * FROM users WHERE email = ?", email, (err, row) => {
    if (err) return done(err);
    if (!row) return done(null, false, { message: 'Incorrect email.' });

    // Check password
    bcrypt.compare(password, row.password, (err, result) => {
      if (err) return done(err);
      if (!result) return done(null, false, { message: 'Incorrect password.' });
      return done(null, row);
    });
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get("SELECT * FROM users WHERE id = ?", id, (err, row) => {
    done(err, row);
  });
});

// Routes
app.post('/signup', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    db.run("INSERT INTO users (email, password) VALUES (?, ?)", req.body.email, hashedPassword, (err) => {
      if (err) {
        // Duplicate entry error
        if (err.errno === 19) {
          res.status(400).send('Email already exists');
        } else {
          res.status(500).send('Internal server error');
        }
      } else {
        res.redirect('/login');
      }
    });
  } catch {
    res.status(500).send('Internal server error');
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Protected route (requires authentication)
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.send('Welcome to your dashboard!');
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
