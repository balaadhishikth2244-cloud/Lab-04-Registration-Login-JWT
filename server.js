
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "lab4_secret_key";

// Temporary user storage
const users = [];

// Home Route
app.get("/", (req, res) => {
    res.json({
        message: "Lab 4 Server is running: Registration, Login and JWT API"
    });
});

// Registration API
app.post("/register", async (req, res) => {
    try {
        const { username, name, password } = req.body;

        // Validate input
        if (!username || !name || !password ||
            !username.trim() || !name.trim() || !password.trim()) {
            return res.status(400).json({
                message: "Username, name and password are required"
            });
        }

        // Check duplicate username
        const existingUser = users.find(
            user => user.username === username
        );

        if (existingUser) {
            return res.status(400).json({
                message: "Username already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = {
            username,
            name,
            password: hashedPassword
        };

        users.push(newUser);

        return res.status(201).json({
            message: "Registration successful",
            user: {
                username: newUser.username,
                name: newUser.name
            }
        });

    } catch (error) {
        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

// Login API
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }

        // Find user
        const user = users.find(
            user => user.username === username
        );

        if (!user) {
            return res.status(400).json({
                message: "Invalid username"
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(400).json({
                message: "Invalid password"
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { username: user.username },
            JWT_SECRET,
            { expiresIn: "1 hour" }
        );

        return res.status(200).json({
            jwt_token: token
        });

    } catch (error) {
        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
