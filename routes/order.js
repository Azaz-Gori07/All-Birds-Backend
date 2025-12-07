import express from "express";
import { getDB } from "../config/db.js";
import { verifyUser } from "../middleware/authMiddleware.js";
import { getUserOrders } from "../controllers/ordersControlles.js";

const router = express.Router();

router.get("/user/:userId", getUserOrders);

router.get("/", async (req, res) => {
  try {
    const db = getDB();
    const orders = await db
      .collection("orders")
      .find({})
      .sort({ created_at: -1 })
      .toArray();

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: `database error ${err}` });
  }
});

router.get("/recent", async (req, res) => {
  const days = Number(req.query.days) || 7;
  try {
    const db = getDB();
    const fromDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const orders = await db
      .collection("orders")
      .find({ created_at: { $gte: fromDate } })
      .sort({ created_at: -1 })
      .toArray();

    res.json(orders);
  } catch {
    res.status(500).json({ error: "Failed to fetch recent orders" });
  }
});

router.get("/:id", async (req, res) => {
  const orderId = Number(req.params.id);
  if (!orderId) return res.status(400).json({ error: "Valid order ID is required" });

  try {
    const db = getDB();
    const order = await db.collection("orders").findOne({ id: orderId });

    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json(order);
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

router.put("/:id/status", async (req, res) => {
  const { status } = req.body;
  const id = Number(req.params.id);
  if (!status) return res.status(400).json({ error: "status is required" });

  try {
    const db = getDB();
    const result = await db
      .collection("orders")
      .updateOne({ id }, { $set: { status } });

    if (result.matchedCount === 0)
      return res.status(404).json({ error: "Order not found" });

    res.json({ message: "Order status updated successfully" });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

router.post("/", verifyUser, async (req, res) => {
  const userId = req.user.id;
  const { items, total, shipping, payment } = req.body;

  if (!items || !total || !shipping || !payment) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const db = getDB();

    const lastOrder = await db
      .collection("orders")
      .find()
      .sort({ id: -1 })
      .limit(1)
      .toArray();

    const newId = lastOrder.length ? lastOrder[0].id + 1 : 1;

    await db.collection("orders").insertOne({
      id: newId,
      user_id: userId,
      items,
      total,
      shipping_name: shipping.name,
      shipping_address: shipping.address,
      shipping_city: shipping.city,
      shipping_pincode: shipping.pincode,
      shipping_phone: shipping.phone,
      payment,
      status: "pending",
      created_at: new Date()
    });

    res.json({ success: true, orderId: newId });
  } catch {
    res.status(500).json({ message: "Failed to place order" });
  }
});

export default router;
