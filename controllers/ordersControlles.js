import db from "../config/db.js";

export const getUserOrders = async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  try {
    const [rows] = await db.promise().query(
      "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );

    res.json(rows);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ error: "Database error" });
  }
};