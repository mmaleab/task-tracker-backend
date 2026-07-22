require('dotenv').config();
const { Pool } = require('pg');

// استخدام DATABASE_URL المضاف في Render مع دعم الاتصال المحلي كبديل
const connectionString = process.env.DATABASE_URL;

const pool = new Pool(
  connectionString
    ? {
        connectionString,
        ssl: { rejectUnauthorized: false }, // مطلوب للاتصال بقواعد بيانات PostgreSQL السحابية
      }
    : {
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
      }
);

// إنشاء جميع الجداول المطلوبة تلقائياً إن لم تكن موجودة
const initDb = async () => {
  try {
    // 1. جدول المستخدمين
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. جدول المهام النشطة
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        due_date DATE,
        due_time TIME,
        is_completed BOOLEAN DEFAULT false,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. جدول المهام المؤرشفة
    await pool.query(`
      CREATE TABLE IF NOT EXISTS archived_tasks (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        due_date DATE,
        due_time TIME,
        is_completed BOOLEAN,
        week_start_date DATE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ All tables are verified and ready!");
  } catch (err) {
    console.error("❌ Error initializing database tables:", err);
  }
};

initDb();

module.exports = pool;