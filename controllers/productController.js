import db from "../config/db.js";


export const getProducts = ( req , res) => {
    db.query("SELECT * FROM products", (err, result) => {
        if (err) throw err;
        res.json(result[0] || {});
    });
};


export const getProductsById = (req, res) => {
    const { id } = req.params;
    db.query("SELECT * FROM products WHERE id = ? " , [id], (err, result) => {
        if (err) throw err;
        res.json(result[0] || {});
    });
};