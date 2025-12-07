import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { getDB } from "../config/db.js";
import { authenticateToken, authorizeRoles } from "../middleware/authMiddleware.js";
import { sendEmail } from "../utils/sendEmail.js";

const router = express.Router();

let otpStore = {};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000);


const sendOTPEmail = async (email, otp, type = "signup") => {
  const SUPPORT_EMAIL = "support@allbirdsweb.com";
  const APP_NAME = "AllBirdsWeb";

  const subject =
    type === "signup" ? "Verify Your Email" : "Password Reset Request";

  const message =
    type === "signup"
      ? `Hello,

Your verification OTP: ${otp}
Valid for 10 minutes.

Regards,
${APP_NAME}`
      : `Hello,

Your password reset OTP: ${otp}
Valid for 5 minutes.

Regards,
${APP_NAME}`;

  await sendEmail(email, subject, message);
};


router.post("/send-signup-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const db = getDB();
    const existing = await db.collection("users").findOne({ email });

    if (existing)
      return res.status(400).json({ error: "Email already registered" });

    const otp = generateOTP();
    otpStore[email] = { otp, createdAt: Date.now(), type: "signup" };

    await sendOTPEmail(email, otp, "signup");

    setTimeout(() => delete otpStore[email], 10 * 60 * 1000);

    res.json({ success: true, message: "OTP sent to your email" });
  } catch {
    res.status(500).json({ error: "Failed to send OTP" });
  }
});


router.post("/verify-and-signup", async (req, res) => {
  const { email, otp, name, password } = req.body;
  if (!email || !otp || !name || !password)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const db = getDB();

    const storedOTP = otpStore[email];
    if (!storedOTP) return res.status(400).json({ error: "OTP expired" });

    if (Date.now() - storedOTP.createdAt > 10 * 60 * 1000) {
      delete otpStore[email];
      return res.status(400).json({ error: "OTP expired" });
    }

    if (storedOTP.otp != otp)
      return res.status(400).json({ error: "Invalid OTP" });

    const existing = await db.collection("users").findOne({ email });
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const lastUser = await db
      .collection("users")
      .find()
      .sort({ id: -1 })
      .limit(1)
      .toArray();

    const newId = lastUser.length ? lastUser[0].id + 1 : 1;

    await db.collection("users").insertOne({
      id: newId,
      name,
      email,
      password: hashedPassword,
      role: "user",
      created_at: new Date()
    });

    delete otpStore[email];
    res.status(201).json({ success: true, message: "Account created successfully" });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});


router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const db = getDB();
    const user = await db.collection("users").findOne({ email });

    if (!user)
      return res.status(401).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});


router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const db = getDB();
    const user = await db.collection("users").findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = generateOTP();
    otpStore[email] = { otp, createdAt: Date.now(), type: "forgot-password" };

    await sendOTPEmail(email, otp, "forgot-password");

    setTimeout(() => delete otpStore[email], 5 * 60 * 1000);

    res.json({ success: true, message: "OTP sent successfully" });
  } catch {
    res.status(500).json({ message: "Error sending OTP" });
  }
});


router.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!otpStore[email] || otpStore[email].otp != otp)
    return res.status(400).json({ message: "OTP invalid or expired" });

  try {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { email },
      { $set: { password: hashedPassword } }
    );

    delete otpStore[email];
    res.json({ success: true, message: "Password reset successfully" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


router.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: "Welcome", user: req.user });
});

router.get(
  "/admin",
  authenticateToken,
  authorizeRoles("admin", "superadmin"),
  (req, res) => res.json({ message: "Welcome Admin", user: req.user })
);

router.get(
  "/superadmin",
  authenticateToken,
  authorizeRoles("superadmin"),
  (req, res) => res.json({ message: "Welcome Super Admin", user: req.user })
);

export default router;
