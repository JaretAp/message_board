const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const app = express();

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        console.log("Connected to database at path: ./users.db");

        // Create the users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Create the messages table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) {
                console.error("Error creating messages table:", err.message);
            } else {
                console.log("Messages table created successfully");
            }
        });
    }
});

// Middleware for parsing form data and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Initialize session management
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport's Local Strategy
passport.use(new LocalStrategy(
    { usernameField: 'username' },
    (username, password, done) => {
        db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
            if (err) return done(err);
            if (!user) return done(null, false, { message: 'Incorrect username.' });

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) return done(null, false, { message: 'Incorrect password.' });
            return done(null, user);
        });
    }
));

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, user) => {
        if (err) return done(err);
        done(null, user);
    });
});

// Set view engine and views folder
app.set('view engine', 'ejs');
app.set('views', './views');

// Authentication middleware
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

// Login and registration routes
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).send("All fields are required");
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
        if (err) return res.status(500).send("Database error");
        if (row) return res.status(400).send("Email already in use");

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function(err) {
                if (err) return res.status(500).send("Error registering user");
                res.send("User registered successfully");
            });
    });
});

// Login route with Passport authentication
app.post('/login', passport.authenticate('local', {
    successRedirect: '/feed',
    failureRedirect: '/login',
    failureMessage: true
}));

// Protected feed route to display all messages
app.get('/feed', ensureAuthenticated, (req, res) => {
    const query = `
        SELECT messages.content, messages.timestamp, users.username 
        FROM messages 
        JOIN users ON messages.user_id = users.id 
        ORDER BY messages.timestamp DESC
    `;

    db.all(query, (err, rows) => {
        if (err) {
            res.status(500).send("Error retrieving messages");
            return;
        }
        res.render('feed', { messages: rows });
    });
});

// Route to handle posting a new message
app.post('/messages', ensureAuthenticated, (req, res) => {
    const userId = req.user.id;
    const content = req.body.content;

    if (!content) {
        return res.status(400).send("Message content is required");
    }

    db.run("INSERT INTO messages (user_id, content) VALUES (?, ?)", [userId, content], (err) => {
        if (err) {
            res.status(500).send("Error saving message");
            return;
        }
        res.redirect('/feed');
    });
});

// Profile and logout routes
app.get('/profile', ensureAuthenticated, (req, res) => {
    res.render('profile', { user: req.user });
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
