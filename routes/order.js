import express from "express";
import db from "../config/db.js";
import { verifyUser }  from "../middleware/authMiddleware.js";

const router = express.Router();


router.post("/verify", verifyUser, (req, res) => {
  res.json({ message: "Token is valid", user: req.user });
});

router.get("/", (req, res) => {
  db.query(
    `SELECT 
      id, 
      created_at, 
      shipping_name, 
      payment, 
      total, 
      shipping_address, 
      shipping_city, 
      shipping_pincode,
      shipping_phone,
      items, 
      status,
      user_id
    FROM orders 
    ORDER BY created_at DESC`,
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: `database error ${err}` });
      }

      res.json(results);
    }
  );
});

router.get("/recent", async (req, res) => {
  const days = req.query.days || 7;
  try {
    // ✅ use db.promise().query() instead of db.query()
    const [rows] = await db.promise().query(
      `SELECT * FROM orders 
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       ORDER BY created_at DESC`,
      [days]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching recent orders:", error);
    res.status(500).json({ error: "Failed to fetch recent orders" });
  }
});



// Get single order by ID
router.get("/:id", (req, res) => {
  const orderId = req.params.id;

  if (!orderId || isNaN(orderId)) {
    return res.status(400).json({ error: "Valid order ID is required" });
  }

  db.query(
    `SELECT 
      id, 
      created_at, 
      shipping_name, 
      payment, 
      total, 
      shipping_address, 
      shipping_city, 
      shipping_pincode,
      shipping_phone,
      items, 
      status,
      user_id
    FROM orders WHERE id = ?`,
    [orderId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }

      res.json(results[0]);
    }
  );
});


// ✅ Update order status //
router.put("/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "status is required" });
  }

  const query = "UPDATE orders SET status = ? WHERE id = ?"
  db.query(query, [status, id], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json({ message: "Order status updated successfully" });
  });
});

// ✅ Place new order
router.post("/", (req, res) => {
  const { user_id, items, total, shipping, payment } = req.body;

  if (!user_id || !items || !total || !shipping) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const query = `
    INSERT INTO orders 
    (user_id, items, total, shipping_name, shipping_address, shipping_city, shipping_pincode, shipping_phone, payment)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [
      user_id,
      JSON.stringify(items), // 👈 cart items JSON me save honge
      total,
      shipping.name,
      shipping.address,
      shipping.city,
      shipping.pincode,
      shipping.phone,
      payment,
    ],
    (err, result) => {
      if (err) {
        console.error("Order Insert Error:", err);
        return res.status(500).json({ message: "Failed to place order" });
      }
      res.json({ success: true, orderId: result.insertId });
    }
  );
});

export default router;
