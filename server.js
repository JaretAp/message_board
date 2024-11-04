const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const app = express();
const moment = require("moment-timezone");

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
    // Query to retrieve top-level messages ordered by latest activity (including replies)
    const query = `
        SELECT m.id, m.content, m.timestamp, u.username, m.parent_id,
               MAX(COALESCE(r.timestamp, m.timestamp)) AS latest_activity
        FROM messages m
        JOIN users u ON m.user_id = u.id
        LEFT JOIN messages r ON r.parent_id = m.id OR r.id = m.id
        WHERE m.parent_id IS NULL
        GROUP BY m.id
        ORDER BY latest_activity DESC;
    `;

    // First query: Get the top-level messages
    db.all(query, (err, parentMessages) => {
        if (err) {
            console.error("Database error:", err.message);
            res.status(500).send("Error retrieving messages");
            return;
        }

        // Convert timestamps of parent messages to Eastern Time
        parentMessages.forEach(msg => {
            msg.timestamp = moment.utc(msg.timestamp).tz("America/New_York").format("YYYY-MM-DD HH:mm:ss");
            msg.replies = []; // Initialize an empty array for replies
        });

        // Second query: Get all replies
        const replyQuery = `
            SELECT r.id, r.content, r.timestamp, u.username, r.parent_id
            FROM messages r
            JOIN users u ON r.user_id = u.id
            WHERE r.parent_id IS NOT NULL
            ORDER BY r.timestamp ASC;
        `;

        db.all(replyQuery, (err, replies) => {
            if (err) {
                console.error("Database error:", err.message);
                res.status(500).send("Error retrieving replies");
                return;
            }

            // Convert timestamps of replies to Eastern Time
            replies.forEach(reply => {
                reply.timestamp = moment.utc(reply.timestamp).tz("America/New_York").format("YYYY-MM-DD HH:mm:ss");
            });

            // Associate replies with their respective parent messages
            parentMessages.forEach(parent => {
                parent.replies = replies.filter(reply => reply.parent_id === parent.id).reverse();
            });

            // Render the view with the organized messages
            res.render('feed', { messages: parentMessages });
        });
    });
});



// Replies Route
app.post('/reply', ensureAuthenticated, (req, res) => {
    const userId = req.user.id;
    const content = req.body.content;
    const parentId = req.body.parent_id;  // The ID of the message being replied to

    if (!content) {
        return res.status(400).send("Reply content is required");
    }

    db.run("INSERT INTO messages (user_id, content, parent_id) VALUES (?, ?, ?)", [userId, content, parentId], (err) => {
        if (err) {
            res.status(500).send("Error saving reply");
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
