import { getDB } from "../config/db.js";

// GET ALL PRODUCTS (same behavior: only first product)
export const getProducts = async (req, res) => {
  try {
    const db = getDB();

    const product = await db
      .collection("products")
      .findOne({});

    res.json(product || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
};

// GET PRODUCT BY ID
export const getProductsById = async (req, res) => {
  const { id } = req.params;

  try {
    const db = getDB();

    const product = await db
      .collection("products")
      .findOne({ id: Number(id) });

    res.json(product || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
};
