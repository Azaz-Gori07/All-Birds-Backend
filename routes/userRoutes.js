// routes/userRoutes.js
import express from "express";
import db from "../config/db.js";
const router = express.Router();
import bcrypt from "bcryptjs";
import { verifyUser } from "../middleware/authMiddleware.js";

router.get("/", (req, res) => {
  db.query("SELECT id, name, email, role, created_at FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results);
  });
});


router.get("/:id", (req, res) => {
  db.query("SELECT id, name, email, role, created_at FROM users WHERE id=?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(results[0]);
  });
});



router.put("/:id/password", verifyUser, async (req, res) => {
  const userId = req.params.id;
  const { currentPassword, newPassword } = req.body;

  // ✅ Token se verify karo ki user apna hi password change kar raha hai
  if (req.user.id !== parseInt(userId)) {
    return res.status(403).json({ message: "Unauthorized: cannot change another user's password" });
  }

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "Current and new password required" });
  }

  try {
    // 🧠 Get current user from DB
    const [rows] = await db.promise().query("SELECT password FROM users WHERE id = ?", [userId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];

    // 🔐 Compare current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    // 🔑 Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 🧱 Update DB
    await db.promise().query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, userId]);

    res.json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).json({ message: "Server error while changing password" });
  }
});



router.post("/", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  } if (Number(req.user.id) !== Number(userId)) {
    return res.status(403).json({ message: "Unauthorized: cannot change another user's password" });
  }


  try {
    const hashedPassword = await bcrypt.hash(password, 8);

    const [result] = await db.promise().query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashedPassword, role]
    );

    return res.status(201).json({
      id: result.insertId,
      name,
      email,
      role,
    });
  }
  catch (err) {
    console.error("❌ Database error:", err.message);
    return res.status(500).json({ message: "Database error", error: err.message });
  }
});



// Update user
router.put("/:id", (req, res) => {
  const { name, email, role } = req.body;
  db.query(
    "UPDATE users SET name=?, email=?, role=? WHERE id=?",
    [name, email, role, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: "Database error" });
      db.query("SELECT id,name,email,role FROM users WHERE id=?",
        [req.params.id],
        (err2, rows) => {
          if (err2) return res.status(500).json({ error: "Database error" });
          res.json(rows[0]);
        }
      );
    }
  );
});

// Delete user
router.delete("/:id", (req, res) => {
  db.query("DELETE FROM users WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ success: true });
  });
});

export default router;
