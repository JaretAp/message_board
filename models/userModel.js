const bcrypt = require('bcrypt');
const db = require('../database'); // Import the database connection

// Function to check if an email already exists
function emailExists(email) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT email FROM users WHERE email = ?`, [email], (err, row) => {
            if (err) {
                reject("Database error");
            } else {
                resolve(row ? true : false);
            }
        });
    });
}

// Function to create a new user, now includes email check
async function createUser(username, email, password) {
    try {
      console.log("checking if email exists:", email);

        // Check if the email already exists
        const exists = await emailExists(email);
        if (exists) {
            console.log("Email already in use");
            return "Email already in use"; // Return an indication of duplicate email
        }

        console.log("Hashing password for user:", username);
        // Hash the password and insert the new user if email is unique
        const hashedPassword = await bcrypt.hash(password, 10);

        return new Promise((resolve, reject) => {
          db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hashedPassword], (err) => {
              if (err) {
                  console.error("Error inserting user:", err.message);
              } else {
                  console.log("User added successfully.");
                  resolve("User registered successfully");
              }
          });
        });
    } catch (err) {
        console.error("Error in createUser:", err.message);
        return "Error registering user";
    }
}

// Function to authenticate a user
async function authenticateUser(username, password) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
            if (err) {
                console.error("Error fetching user:", err.message);
                reject("Database error");
                return;
            }
            if (user && await bcrypt.compare(password, user.password)) {
                resolve("Authentication successful");
            } else {
                resolve("Authentication failed");
            }
        });
    });
}

// Export the functions for use in other files
module.exports = { createUser, authenticateUser };
