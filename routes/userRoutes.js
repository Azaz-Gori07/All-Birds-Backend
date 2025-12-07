import express from "express";
import { getDB } from "../config/db.js";
import bcrypt from "bcryptjs";
import { verifyUser } from "../middleware/authMiddleware.js";

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const db = getDB();
    const users = await db
      .collection("users")
      .find({}, { projection: { password: 0 } })
      .toArray();
    res.json(users);
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

router.get("/:id", async (req, res) => {
  const id = Number(req.params.id);
  try {
    const db = getDB();
    const user = await db
      .collection("users")
      .findOne({ id }, { projection: { password: 0 } });

    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

router.put("/:id/password", verifyUser, async (req, res) => {
  const userId = Number(req.params.id);
  const { currentPassword, newPassword } = req.body;

  if (req.user.id !== userId) {
    return res.status(403).json({ message: "Unauthorized: cannot change another user's password" });
  }

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "Current and new password required" });
  }

  try {
    const db = getDB();
    const user = await db.collection("users").findOne({ id: userId });

    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { id: userId },
      { $set: { password: hashedPassword } }
    );

    res.json({ success: true, message: "Password changed successfully" });
  } catch {
    res.status(500).json({ message: "Server error while changing password" });
  }
});

router.post("/create", verifyUser, async (req, res) => {
  const { name, email, password, role } = req.body;

  if (req.user.role !== "superadmin") {
    return res.status(403).json({ message: "Access denied: only superadmins can create users" });
  }

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const db = getDB();
    const existing = await db.collection("users").findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 8);

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
      role,
      created_at: new Date()
    });

    res.status(201).json({ id: newId, name, email, role });
  } catch (err) {
    res.status(500).json({ message: "Database error", error: err.message });
  }
});

router.put("/:id", async (req, res) => {
  const { name, email, role } = req.body;
  const id = Number(req.params.id);

  try {
    const db = getDB();
    await db.collection("users").updateOne(
      { id },
      { $set: { name, email, role } }
    );

    const user = await db
      .collection("users")
      .findOne({ id }, { projection: { password: 0 } });

    res.json(user);
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

router.delete("/:id", async (req, res) => {
  const id = Number(req.params.id);
  try {
    const db = getDB();
    await db.collection("users").deleteOne({ id });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

export default router;
