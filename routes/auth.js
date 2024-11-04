const express = require('express');
const router = express.Router();
const { createUser, authenticateUser } = require('../models/userModel'); // Import functions

// Registration route
router.post('/register', async (req, res) => {
    console.log("Register route called with data:", req.body);

    const { username, email, password } = req.body;
    
    // Check if all required fields are present
    if (!username || !email || !password) {
        console.log("Missing registration fields");
        return res.status(400).send("All fields are required");
    }

    try {
        const result = await createUser(username, email, password);
        console.log("createUser result:", result); // Log the result of createUser

        if (result === "User registered successfully") {
            res.send(result);
        } else if (result === "Email already in use") {
            res.status(400).send(result);
        } else {
            res.status(500).send("Error registering user");
        }
    } catch (error) {
        console.error("Error in registration route:", error.message);
        res.status(500).send("Unexpected error during registration");
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await authenticateUser(username, password);
        res.send(result);
    } catch (error) {
        console.error("Error in login route:", error.message);
        res.status(500).send("Unexpected error during login");
    }
});

module.exports = router;
