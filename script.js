const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS work_log (id INTEGER PRIMARY KEY, user_id INTEGER, date TEXT, start_time TEXT, end_time TEXT, breaks INTEGER, total_hours REAL, FOREIGN KEY(user_id) REFERENCES users(id))");
});

// Passport local strategy for user authentication
passport.use(new LocalStrategy((username, password, done) => {
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });

    bcrypt.compare(password, user.password, (err, res) => {
      if (res) return done(null, user);
      else return done(null, false, { message: 'Incorrect password.' });
    });
  });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    done(err, user);
  });
});

// Routes
app.post('/login', passport.authenticate('local', { failureRedirect: '/login.html' }), (req, res) => {
  res.redirect('/');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (user) return res.status(400).json({ error: 'User already exists' });

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });

      db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, username });
      });
    });
  });
});

app.post('/log-hours', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });

  const { date, startTime, endTime, breaks } = req.body;
  const start = new Date(`2000-01-01T${startTime}`);
  const end = new Date(`2000-01-01T${endTime}`);
  const diffInMinutes = (end - start) / 60000;
  const totalHours = (diffInMinutes - parseInt(breaks)) / 60;

  db.run("INSERT INTO work_log (user_id, date, start_time, end_time, breaks, total_hours) VALUES (?, ?, ?, ?, ?, ?)",
    [req.user.id, date, startTime, endTime, breaks, totalHours], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, date, startTime, endTime, breaks, totalHours });
    });
});

app.get('/logs', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });

  db.all("SELECT * FROM work_log WHERE user_id = ?", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
