import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../config/db.js';
import { authenticateToken, authorizeRoles } from "../middleware/authMiddleware.js";


const router = express.Router();

// signup //
router.post("/signup", (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "Please fill all the fields" });
    }


    //check if user already exists //
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).json({ error: "DB error" });

        if (result.length > 0) {
            return res.status(400).json({ error: "Email already registered" });
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            [name, email, hashedPassword, role || "user"],
            (err, result) => {
                if (err) return res.status(500).json({ error: "DB insert failed" });
                res.status(201).json({ message: "User registered successfully" });
            }
        );
    });
});


//login //
router.post("/login", (req, res) => {
    const { email, password } = req.body;


    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).json({ error: "Db error" });

        if (result.length === 0) {
            return res.status(401).json({ error: "invalid email or password" });
        }

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: "invalid email or password" });
        }


        // generate tokem //
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ message: "login successful", token, role: user.role });
    });
});


// 🔹 Profile (Any logged-in user)
router.get("/profile", authenticateToken, (req, res) => {
    res.json({ message: "Welcome", user: req.user });
});

// 🔹 Admin-only route
router.get("/admin", authenticateToken, authorizeRoles("admin", "superadmin"), (req, res) => {
    res.json({ message: "Welcome Admin", user: req.user });
});

// 🔹 Super Admin-only route
router.get("/superadmin", authenticateToken, authorizeRoles("superadmin"), (req, res) => {
    res.json({ message: "Welcome Super Admin", user: req.user });
});


export default router;