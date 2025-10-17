// routes/userRoutes.js
import express from "express";
import db from "../config/db.js";
const router = express.Router();
import bcrypt from "bcryptjs";

router.get("/", (req, res) => {
  db.query("SELECT id, name, email, role, created_at FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results);
  });
});


router.post("/", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
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
  } catch (err) {
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
