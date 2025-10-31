import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { authenticateToken, authorizeRoles } from "../middleware/authMiddleware.js";
import { sendEmail } from "../utils/sendEmail.js"; // 👈 utility for sending emails

const router = express.Router();

// ===================== SIGNUP =====================
router.post("/signup", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Please fill all the fields" });
  }

  try {
    const [existing] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db
      .promise()
      .query("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", [
        name,
        email,
        hashedPassword,
        role || "user",
      ]);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== LOGIN =====================
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) return res.status(401).json({ error: "Invalid email or password" });

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error ////" });
  }
});

// ===================== PROFILE (Any Logged User) =====================
router.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: "Welcome", user: req.user });
});

// ===================== ADMIN ONLY =====================
router.get("/admin", authenticateToken, authorizeRoles("admin", "superadmin"), (req, res) => {
  res.json({ message: "Welcome Admin", user: req.user });
});

// ===================== SUPERADMIN ONLY =====================
router.get("/superadmin", authenticateToken, authorizeRoles("superadmin"), (req, res) => {
  res.json({ message: "Welcome Super Admin", user: req.user });
});

// ===================== FORGOT PASSWORD SYSTEM =====================

// temporary store for OTPs (⚠️ reset after server restart)
let otpStore = {};

// ✅ 1️⃣ Send OTP
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const [rows] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(404).json({ message: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    otpStore[email] = { otp, createdAt: Date.now() };

    await sendEmail(
      email,
      "Password Reset OTP",
      `Your OTP is ${otp}. It will expire in 5 minutes.`
    );

    console.log(`✅ OTP sent to ${email}: ${otp}`);

    // expire after 5 min
    setTimeout(() => delete otpStore[email], 5 * 60 * 1000);

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ message: "Error sending OTP" });
  }
});

// ✅ 2️⃣ Verify OTP
router.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) return res.status(400).json({ message: "No OTP found for this email" });

  const storedOTP = otpStore[email];
  const isExpired = Date.now() - storedOTP.createdAt > 5 * 60 * 1000;

  if (isExpired) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired" });
  }

  if (storedOTP.otp == otp) {
    return res.json({ success: true, message: "OTP verified successfully" });
  } else {
    return res.status(400).json({ message: "Invalid OTP" });
  }
});

// ✅ 3️⃣ Reset Password
router.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!otpStore[email] || otpStore[email].otp != otp) {
    return res.status(400).json({ message: "OTP invalid or expired" });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.promise().query("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, email]);

    delete otpStore[email];
    res.json({ success: true, message: "Password reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
