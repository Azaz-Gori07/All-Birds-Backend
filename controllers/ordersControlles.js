import { getDB } from "../config/db.js";

export const getUserOrders = async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  try {
    const db = getDB();

    const orders = await db
      .collection("orders")
      .find({ user_id: userId })
      .sort({ created_at: -1 })
      .toArray();

    res.json(orders);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ error: "Database error" });
  }
};
