const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Creates a login token that expires in 7 days
const createToken = (userId, role) => {
    return jwt.sign({ id: userId, role }, process.env.JWT_SECRET, {
        expiresIn: "7d",
    });
};

// Shapes the user data we send back (never the password)
const publicUser = (user) => ({
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
});

// POST /api/auth/register
const register = async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;

        if (!name || !email || !password) {
            return res
                .status(400)
                .json({ message: "Name, email and password are required" });
        }

        if (password.length < 6) {
            return res
                .status(400)
                .json({ message: "Password must be at least 6 characters" });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({ message: "Email is already registered" });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email, phone, passwordHash });

        res.status(201).json({
            message: "Registration successful",
            token: createToken(user._id, user.role),
            user: publicUser(user),
        });
    } catch (error) {
        console.error("Register error:", error.message);
        res.status(500).json({ message: "Something went wrong on the server" });
    }
};

// POST /api/auth/login
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Check both fields are filled
        if (!email || !password) {
            return res
                .status(400)
                .json({ message: "Email and password are required" });
        }

        // 2. Find the user. "+passwordHash" asks for the hidden password field.
        const user = await User.findOne({ email: email.toLowerCase() }).select(
            "+passwordHash"
        );

        // 3. Compare the typed password with the scrambled one
        // (an account without a passwordHash, e.g. one added by hand in Atlas, can't log in)
        const passwordMatches =
            user &&
            typeof user.passwordHash === "string" &&
            (await bcrypt.compare(password, user.passwordHash));

        // Same message for both cases, so attackers can't tell which emails exist
        if (!passwordMatches) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // 4. Block suspended accounts
        if (user.status !== "active") {
            return res
                .status(403)
                .json({ message: "Your account is suspended. Contact support." });
        }

        // 5. Remember when they last logged in
        // updateOne skips full-document validation, so an older/odd record can't crash login
        await User.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });

        res.json({
            message: "Login successful",
            token: createToken(user._id, user.role),
            user: publicUser(user),
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Something went wrong on the server" });
    }
};

// GET /api/auth/me (only for logged-in users)
const getMe = async (req, res) => {
    // req.user was filled in by the auth middleware
    res.json({ user: publicUser(req.user) });
};

module.exports = { register, login, getMe };