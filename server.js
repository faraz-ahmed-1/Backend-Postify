require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ======================
// ✅ MySQL POOL (FIXED)
// ======================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false }
});

db.getConnection((err, conn) => {
  if (err) console.error("❌ MySQL Pool Error:", err);
  else {
    console.log("✅ MySQL Pool Connected");
    conn.release();
  }
});

// ======================
// Static uploads
// ======================
app.use("/uploads", express.static("uploads"));

// ======================
// Multer config
// ======================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// ======================
// Health check
// ======================
app.get("/", (req, res) => res.json({ ok: true }));

// ======================
// AUTH
// ======================
app.post("/api/signup", async (req, res) => {
  const { fullName, username, email, password } = req.body;
  if (!fullName || !username || !email || !password)
    return res.status(400).json({ error: "All fields required" });

  const checkSql = "SELECT 1 FROM Users WHERE email = ? OR username = ?";
  db.query(checkSql, [email, username], async (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (rows.length) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const insertSql =
      "INSERT INTO Users (username,email,password_hash,full_name,created_at) VALUES (?,?,?,?,NOW())";

    db.query(insertSql, [username, email, hash, fullName], err2 => {
      if (err2) return res.status(500).json({ error: "Signup failed" });
      res.json({ success: true });
    });
  });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const sql =
    "SELECT user_id,username,email,password_hash,full_name,profile_pic FROM Users WHERE email=?";
  db.query(sql, [email], async (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!rows.length) return res.status(404).json({ error: "User not found" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid password" });

    res.json({ success: true, user });
  });
});

// ======================
// PROFILE
// ======================
app.post("/api/edit-profile", upload.single("profile_pic"), async (req, res) => {
  const { username, full_name, bio, password } = req.body;
  if (!username) return res.status(400).json({ error: "Username required" });

  const updates = [];
  const values = [];

  if (full_name) {
    updates.push("full_name=?");
    values.push(full_name);
  }
  if (bio) {
    updates.push("bio=?");
    values.push(bio);
  }
  if (password) {
    const hash = await bcrypt.hash(password, 10);
    updates.push("password_hash=?");
    values.push(hash);
  }
  if (req.file) {
    updates.push("profile_pic=?");
    values.push("/uploads/" + req.file.filename);
  }

  if (!updates.length)
    return res.status(400).json({ error: "Nothing to update" });

  values.push(username);
  const sql = `UPDATE Users SET ${updates.join(",")} WHERE username=?`;

  db.query(sql, values, err => {
    if (err) return res.status(500).json({ error: "Update failed" });
    res.json({ success: true });
  });
});

// ======================
// POSTS
// ======================
app.post("/api/create-post", upload.single("media"), (req, res) => {
  const { username, caption } = req.body;
  if (!username || !caption)
    return res.status(400).json({ error: "Missing fields" });

  let image = null,
    video = null;
  if (req.file) {
    const file = "/uploads/" + req.file.filename;
    if (req.file.mimetype.startsWith("image")) image = file;
    else video = file;
  }

  const sqlUser = "SELECT user_id FROM Users WHERE username=?";
  db.query(sqlUser, [username], (err, rows) => {
    if (err || !rows.length)
      return res.status(500).json({ error: "User error" });

    const postSql =
      "INSERT INTO posts (username,content,image_url,video_url,created_at,user_id) VALUES (?,?,?,?,NOW(),?)";
    db.query(
      postSql,
      [username, caption, image, video, rows[0].user_id],
      err2 => {
        if (err2) return res.status(500).json({ error: "Post failed" });
        res.json({ success: true });
      }
    );
  });
});

// ======================
// LIKE (SINGLE VERSION)
// ======================
app.post("/api/like", (req, res) => {
  const { userId, postId } = req.body;
  const sql = "INSERT IGNORE INTO Likes (user_id,post_id) VALUES (?,?)";
  db.query(sql, [userId, postId], err => {
    if (err) return res.status(500).json({ error: "Like failed" });
    res.json({ liked: true });
  });
});

app.delete("/api/like", (req, res) => {
  const { userId, postId } = req.body;
  const sql = "DELETE FROM Likes WHERE user_id=? AND post_id=?";
  db.query(sql, [userId, postId], err => {
    if (err) return res.status(500).json({ error: "Unlike failed" });
    res.json({ liked: false });
  });
});

// ======================
// COMMENT (SINGLE VERSION)
// ======================
app.post("/api/comment", (req, res) => {
  const { postId, username, comment } = req.body;
  const sql =
    "INSERT INTO comments (post_id,username,comment,created_at) VALUES (?,?,?,NOW())";
  db.query(sql, [postId, username, comment], err => {
    if (err) return res.status(500).json({ error: "Comment failed" });
    res.json({ success: true });
  });
});

// ======================
// SERVER START
// ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);