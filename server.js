
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "lab4_secret_key";

// Middleware
app.use(express.json());

// Temporary user storage
const users = [];

// HOME ROUTE
app.get("/", (req, res) => {
    res.status(200).json({
        message: "Lab 4 Server is running: Registration, Login and JWT API"
    });
});

// REGISTER ROUTE
app.post("/register", async (req, res) => {
    try {
        const { username, name, password } = req.body;

        // Validate input
        if (
            typeof username !== "string" ||
            typeof name !== "string" ||
            typeof password !== "string" ||
            !username.trim() ||
            !name.trim() ||
            !password.trim()
        ) {
            return res.status(400).json({
                message: "Username, name and password are required"
            });
        }

        // Check duplicate username
        const existingUser = users.find(
            user => user.username === username.trim()
        );

        if (existingUser) {
            return res.status(400).json({
                message: "Username already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user
        const newUser = {
            username: username.trim(),
            name: name.trim(),
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
        console.error("Registration error:", error);

        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

// LOGIN ROUTE
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (
            typeof username !== "string" ||
            typeof password !== "string" ||
            !username.trim() ||
            !password
        ) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }

        // Find user
        const user = users.find(
            user => user.username === username.trim()
        );

        if (!user) {
            return res.status(400).json({
                message: "Invalid username"
            });
        }

        // Verify password
        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(400).json({
                message: "Invalid password"
            });
        }

        // Generate JWT
        const token = jwt.sign(
            { username: user.username },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.status(200).json({
            jwt_token: token
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

// Handle unknown routes
app.use((req, res) => {
    res.status(404).json({
        message: "Route not found"
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
