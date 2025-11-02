import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { authenticateToken, authorizeRoles } from "../middleware/authMiddleware.js";
import { sendEmail } from "../utils/sendEmail.js";

const router = express.Router();

let otpStore = {};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000);

const sendOTPEmail = async (email, otp, type = "signup") => {
  const SUPPORT_EMAIL = "support@allbirdsweb.com";
  const APP_NAME = "AllBirdsWeb";

  const subject = type === "signup" ? "Verify Your Email" : "Password Reset Request";
  const message = type === "signup"
    ? `Hello,

Thank you for signing up with ${APP_NAME}!

Your verification OTP: ${otp}

This OTP is valid for 10 minutes.

For your security:
- Do NOT share this OTP with anyone.
- If you did not sign up, please ignore this email or contact us at ${SUPPORT_EMAIL}.

Regards,
${APP_NAME} Team`
    : `Hello,

We received a request to reset the password for your ${APP_NAME} account.

Your OTP: ${otp}

This OTP is valid for 5 minutes.

For your security:
- Do NOT share this OTP with anyone.
- If you did not request a password reset, please change your password immediately or contact our support team at ${SUPPORT_EMAIL}.

Regards,
${APP_NAME} Security Team`;

  await sendEmail(email, subject, message);
};

router.post("/send-signup-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const [existing] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const otp = generateOTP();
    otpStore[email] = {
      otp,
      createdAt: Date.now(),
      type: 'signup'
    };

    await sendOTPEmail(email, otp, 'signup');

    setTimeout(() => delete otpStore[email], 10 * 60 * 1000);

    res.json({ success: true, message: "OTP sent to your email" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

router.post("/verify-and-signup", async (req, res) => {
  const { email, otp, name, password } = req.body;

  if (!email || !otp || !name || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    if (!otpStore[email]) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    const storedOTP = otpStore[email];

    const isExpired = Date.now() - storedOTP.createdAt > 10 * 60 * 1000;
    if (isExpired) {
      delete otpStore[email];
      return res.status(400).json({ error: "OTP expired. Please request a new one" });
    }

    if (storedOTP.otp != otp) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    const [existing] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      delete otpStore[email];
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db
      .promise()
      .query("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", [
        name,
        email,
        hashedPassword,
        "user",
      ]);

    delete otpStore[email];

    res.status(201).json({ success: true, message: "Account created successfully" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/resend-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    if (!otpStore[email]) {
      return res.status(400).json({ error: "No OTP request found. Please start signup again" });
    }

    const otpType = otpStore[email].type || 'signup';

    const otp = generateOTP();
    otpStore[email] = {
      otp,
      createdAt: Date.now(),
      type: otpType
    };

    await sendOTPEmail(email, otp, otpType);

    setTimeout(() => delete otpStore[email], 10 * 60 * 1000);

    res.json({ success: true, message: "OTP resent successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to resend OTP" });
  }
});

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
    res.status(500).json({ error: "Server error" });
  }
});

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
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: "Welcome", user: req.user });
});

router.get("/admin", authenticateToken, authorizeRoles("admin", "superadmin"), (req, res) => {
  res.json({ message: "Welcome Admin", user: req.user });
});

router.get("/superadmin", authenticateToken, authorizeRoles("superadmin"), (req, res) => {
  res.json({ message: "Welcome Super Admin", user: req.user });
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const [rows] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(404).json({ message: "User not found" });

    const otp = generateOTP();
    otpStore[email] = {
      otp,
      createdAt: Date.now(),
      type: 'forgot-password'
    };

    await sendOTPEmail(email, otp, 'forgot-password');

    setTimeout(() => delete otpStore[email], 5 * 60 * 1000);

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error sending OTP" });
  }
});

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
    res.status(500).json({ message: "Server error" });
  }
});

export default router;