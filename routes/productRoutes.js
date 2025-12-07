import express from "express";
import { getDB } from "../config/db.js";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, path.join(__dirname, "../uploads"));
  },
  filename(req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

router.get("/", async (req, res) => {
  try {
    const db = getDB();
    const products = await db.collection("products").find({}).toArray();
    res.json(products);
  } catch {
    res.status(500).json({ error: "Database query failed" });
  }
});

router.get("/:id", async (req, res) => {
  const productId = Number(req.params.id);
  try {
    const db = getDB();
    const product = await db.collection("products").findOne({ id: productId });
    if (!product) return res.status(404).json({ error: "product not found" });
    res.json(product);
  } catch {
    res.status(500).json({ error: "database query failed" });
  }
});

router.post("/", upload.single("image"), async (req, res) => {
  const { name, price, title } = req.body;
  const image = req.file ? req.file.filename : null;

  try {
    const db = getDB();
    const lastProduct = await db
      .collection("products")
      .find()
      .sort({ id: -1 })
      .limit(1)
      .toArray();

    const newId = lastProduct.length ? lastProduct[0].id + 1 : 1;

    await db.collection("products").insertOne({
      id: newId,
      name,
      price,
      title,
      image
    });

    res.status(201).json({
      message: "product created successfully",
      productId: newId,
      image
    });
  } catch {
    res.status(500).json({ error: "database query failed" });
  }
});

router.put("/:id", upload.single("image"), async (req, res) => {
  const productId = Number(req.params.id);
  const { name, price, title } = req.body;
  const image = req.file ? req.file.filename : req.body.image;

  try {
    const db = getDB();
    await db
      .collection("products")
      .updateOne(
        { id: productId },
        { $set: { name, price, title, image } }
      );

    res.json({ message: "product updated successfully" });
  } catch {
    res.status(500).json({ error: "database query failed" });
  }
});

router.delete("/:id", async (req, res) => {
  const productId = Number(req.params.id);
  try {
    const db = getDB();
    await db.collection("products").deleteOne({ id: productId });
    res.json({ message: "product deleted successfully" });
  } catch {
    res.status(500).json({ error: "database query failed" });
  }
});

export default router;
