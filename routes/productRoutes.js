import express from "express";
import db from "../config/db.js";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

//multer storage setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "../uploads"));
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

//product get //
router.get("/", (req, res) => {
  db.query("SELECT * FROM products", (err, results) => {
    if (err) {
      console.error("Error fetching products:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(results);
  });
});


//product get by id//
router.get("/:id", (req, res) => {
  const productId = req.params.id;
  db.query("SELECT * FROM products WHERE id = ?", [productId], (err, result) => {
    if (err) {
      console.log("error fetching product", err);
      return res.status(500).json({ error: "database query failed" })
    };

    if (result.length === 0) {
      return res.status(404).json({ error: "product not found" })
    }
    res.json(result[0])
  });
});


//product post //
router.post("/", upload.single("image"), (req, res) => {
  const { name, price, title } = req.body;
  const image = req.file ? req.file.filename : null;


  db.query("INSERT INTO products (name , price, title, image) VALUES (?, ?, ?, ?)", [name, price, title, image], (err, result) => {
    if (err) {
      console.log("error inserting product", err);
      return res.status(500).json({ error: "database query failed" });
    };
    res.status(201).json({ message: "product created successfully", productId: result.insertId, image });
  }
  );
});


//product update using put //
router.put("/:id", upload.single("image"), (req, res) => {
  const productId = req.params.id;
  const { name, price, title } = req.body;
  const image = req.file ? req.file.filename : req.body.image;

  db.query("UPDATE products SET name = ?, price = ?, title = ?, image = ? WHERE id = ?", [name, price, title, image, productId], (err, result) => {
    if (err) {
      console.log("error updating product", err);
      return res.status(500).json({ error: "database query failed" });
    }
    res.json({ message: "product updated successfully" });
  });
});


//product delete //
router.delete("/:id", (req, res) => {
  const productId = req.params.id;
  db.query("DELETE FROM products WHERE id = ?", [productId], (err, result) => {
    if (err) {
      console.log("error deleting product", err);
      return res.status(500).json({ error: "database query failed" })
    };
    res.json({ message: "product deleted successfully" })
  });
});

export default router;
