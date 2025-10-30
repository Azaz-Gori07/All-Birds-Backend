import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config();

// Create a connection pool directly from URL
const pool = mysql.createPool(process.env.DATABASE_URL);

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Connected to Railway MySQL');
    connection.release();
  }
});

export default pool;
