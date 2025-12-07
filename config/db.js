import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const client = new MongoClient(process.env.MONGODB_URI);
let db;

export const connectDB = async () => {
  if (db) return db;

  try {
    await client.connect();
    db = client.db();
    console.log("✅ Connected to MongoDB");
    return db;
  } catch (error) {
    console.error("❌ MongoDB connection failed", error);
    process.exit(1);
  }
};

export const getDB = () => {
  if (!db) throw new Error("❌ Database not connected");
  return db;
};
