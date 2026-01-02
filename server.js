require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");


// Initialize app
const app = express();
// app.use(bodyParser.json());
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false
  }
});

// Make sure SQL is connected
db.connect(err => {
  if (err) {
    console.error('❌ Database connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL');
});

app.get('/', (req,res) => res.json({ ok: true }));

app.use("/uploads", express.static("uploads"));
// --- Sign Up API ---
app.post('/api/signup', async (req, res) => {
  try {
    const { fullName, username, email, password } = req.body;

    if (!fullName || !username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // 1️⃣ Check if user already exists
    const checkSql = `SELECT * FROM Users WHERE email = ? OR username = ?`;
    db.query(checkSql, [email, username], async (err, results) => {
      if (err) {
        console.error('Error checking user:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      if (results.length > 0) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // 2️⃣ Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // 3️⃣ Insert new user
      const insertSql = `
        INSERT INTO Users (username, email, password_hash, full_name, created_at)
        VALUES (?, ?, ?, ?, NOW())
      `;
      db.query(insertSql, [username, email, hashedPassword, fullName], (err, result) => {
        if (err) {
          console.error('Error inserting user:', err);
          return res.status(500).json({ error: 'Failed to add user' });
        }
        res.status(201).json({ message: 'User added successfully', userId: result.insertId });
      });
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/signup', (req, res) => {
  db.query(
    'SELECT username, email FROM Users',
    (err, results) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      res.json(results);
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT user_id, username, email, password_hash, full_name, profile_pic FROM Users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: err });
      if (results.length === 0) return res.status(400).json({ message: "User not found" });

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password_hash);

      if (!isMatch) return res.status(400).json({ message: "Invalid password" });

      res.json({
        message: "Login successful",
        user: {
          id: user.user_id,
          username: user.username,
          email: user.email,
          fullName: user.full_name,
          profile_pic: user.profile_pic,
        },
      });
    }
  );
});

app.get("/api/profile", (req, res) => {
  const { username, currentUserId } = req.query;

  if (!username) {
    return res.status(400).json({ error: "Username required" });
  }

  const sql = `
    SELECT u.user_id, u.username, u.full_name, u.bio, u.profile_pic,
           (SELECT COUNT(*) FROM Posts p WHERE p.username = u.username) AS postCount,
           (SELECT COUNT(*) FROM followers f WHERE f.following_id = u.user_id) AS followers,
           (SELECT COUNT(*) FROM followers f WHERE f.follower_id = u.user_id) AS following,
           CASE 
             WHEN ? IS NULL THEN 0
             ELSE EXISTS(
               SELECT 1 
               FROM followers f
               WHERE f.follower_id = ? AND f.following_id = u.user_id
             )
           END AS isFollowed
    FROM Users u
    WHERE u.username = ?
  `;

  db.query(sql, [currentUserId || null, currentUserId || null, username], (err, result) => {
    if (err) {
      console.error("Error fetching profile:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const profile = result[0];
    res.json(profile);
  });
});


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // folder for uploads
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // unique filename
  }
});

const upload = multer({ storage: storage });

// --- Edit Profile API ---
app.post("/api/edit-profile", upload.single("profile_pic"), async (req, res) => {
  try {
    const { full_name, bio, email, password, username } = req.body; 
    // ⚠️ username should come from session/token ideally, for now we accept from frontend

    let profilePic = null;
    if (req.file) {
      profilePic = "/uploads/" + req.file.filename;
    }

    // Build SQL dynamically depending on what fields were provided
    let updates = [];
    let values = [];

    if (full_name) {
      updates.push("full_name = ?");
      values.push(full_name);
    }

    if (bio) {
      updates.push("bio = ?");
      values.push(bio);
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push("password_hash = ?");
      values.push(hashedPassword);
    }

    if (profilePic) {
      updates.push("profile_pic = ?");
      values.push(profilePic);
    }

    if (updates.length === 0) {
      return res.status(400).json({ message: "No updates provided" });
    }

    values.push(username); // for WHERE clause

    const sql = `UPDATE Users SET ${updates.join(", ")} WHERE username = ?`;

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error("Error updating profile:", err);
        return res.status(500).json({ message: "Failed to update profile" });
      }

       res.json({
    message: "Profile updated successfully",
    username: username,
    full_name,
    bio,
    email,
    profile_pic: profilePic
  });
    });

  } catch (err) {
    console.error("Edit profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/user/by-username/:username", (req, res) => {
  const username = req.params.username;
  const currentUserId = req.query.currentUserId;

  const sql = `
    SELECT u.user_id, u.username, u.full_name AS name, u.bio, u.profile_pic,
      (SELECT COUNT(*) FROM followers WHERE following_id = u.user_id) AS followers,
      (SELECT COUNT(*) FROM followers WHERE follower_id = u.user_id) AS following,
      EXISTS(SELECT 1 FROM followers WHERE follower_id = ? AND following_id = u.user_id) AS isFollowed
    FROM Users u
    WHERE u.username = ?
  `;

  db.query(sql, [currentUserId, username], (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(results[0]);
  });
});

// --- Create Post API (without user_id) ---
app.post("/api/create-post", upload.single("media"), (req, res) => {
  try {
    const { username, caption } = req.body;
    console.log(username, caption);

    if (!username || !caption) {
      return res.status(400).json({ message: "Username and caption are required" });
    }

    let imageUrl = null;
    let videoUrl = null;

    if (req.file) {
      const filePath = "/uploads/" + req.file.filename;

      if (req.file.mimetype.startsWith("image")) {
        imageUrl = filePath;
      } else if (req.file.mimetype.startsWith("video")) {
        videoUrl = filePath;
      }
    }

    const userIdSQL = `SELECT user_id FROM Users WHERE username = ?`;

    db.query(userIdSQL, [username], (err, results) => {
      if (err) {
        console.error("Error fetching User id:", err);
        return res.status(500).json({ message: "Error fetching user" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const userId = results[0].user_id;

      const insertPostSql = `
        INSERT INTO Posts (username, content, image_url, video_url, created_at, user_id)
        VALUES (?, ?, ?, ?, NOW(), ?)
      `;

      db.query(insertPostSql, [username, caption, imageUrl, videoUrl, userId], (err, result) => {
        if (err) {
          console.error("Error creating post:", err);
          return res.status(500).json({ message: "Failed to create post" });
        }

        res.json({
          message: "Post created successfully ✅",
          postId: result.insertId
        });
      });
    });
  } catch (err) {
    console.error("Create post error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get posts for a user (with likes & comments count)
app.get("/api/user-posts/:username", (req, res) => {
  const { username } = req.params;

  const sql = `
    SELECT 
        p.id,
        p.content,
        p.image_url,
        p.video_url,
        p.created_at,
        u.username,
        u.profile_pic,
        COUNT(DISTINCT l.id) AS like_count,
        COUNT(DISTINCT c.id) AS comment_count
    FROM Posts p
    JOIN Users u ON p.username = u.username
    LEFT JOIN Likes l ON l.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    WHERE u.username = ?
    GROUP BY p.id, p.content, p.image_url, p.video_url, p.created_at, u.username, u.profile_pic
    ORDER BY p.created_at DESC
  `;

  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching posts:", err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json(results);
  });
});

app.get("/api/post/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
  SELECT p.id, p.username, p.content, p.image_url, p.video_url, p.created_at, u.profile_pic
  FROM Posts p
  JOIN Users u ON p.username = u.username
  WHERE p.id = ?
  `;


  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error fetching post:", err);
      return res.status(500).json({ message: "Failed to fetch post" });
    }
    res.json(result[0]);
  });
});

// DELETE a post
app.delete("/api/post/:id", (req, res) => {
  const { id } = req.params;
  console.log('post id: ', id);
  const sql = `DELETE FROM Posts WHERE id = ?`;

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting post:", err);
      return res.status(500).json({ success: false, message: "Failed to delete post" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    res.json({ success: true, message: "Post deleted successfully" });
  });
});

// Like a post
app.post("/api/like", (req, res) => {
  const { username, postId, userId } = req.body;

  if (!postId || !userId || !username) {
    return res.status(400).json({ error: "Missing data" });
  }

  // 1️⃣ Find post owner
  const findOwnerSql = "SELECT user_id FROM Posts WHERE id = ?";
  db.query(findOwnerSql, [postId], (err, postResults) => {
    if (err) {
      console.error("❌ Find owner error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (postResults.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const ownerId = postResults[0].user_id;

    // 2️⃣ Check if THIS user already liked THIS post
    const checkSql = `SELECT id FROM Likes WHERE post_id = ? AND user_id = ?`;
    db.query(checkSql, [postId, userId], (err, results) => {
      if (err) {
        console.error("❌ Like fetch error:", err);
        return res.status(500).json({ error: "Like fetch error" });
      }

      if (results.length === 0) {
        // 3️⃣ Not liked yet → Insert like
        const likeSql = `
          INSERT INTO Likes (post_id, user_id, username)
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE created_at = NOW()
        `;
        db.query(likeSql, [postId, userId, username], (err) => {
          if (err) {
            console.error("❌ Like insert error:", err);
            return res.status(500).json({ error: "Like insert error" });
          }

          // 🔔 Create notification (don’t notify yourself)
          if (userId !== ownerId) {
            createNotification(userId, ownerId, "like", postId);
          }

          // Return updated like count
          const countSql = `SELECT COUNT(*) AS count FROM Likes WHERE post_id = ?`;
          db.query(countSql, [postId], (err2, result) => {
            if (err2) {
              console.error("❌ Count error:", err2);
              return res.status(500).json({ error: "Count error" });
            }
            res.json({ liked: true, count: result[0].count });
          });
        });
      } else {
        // 4️⃣ Already liked → Unlike
        const deleteSql = `DELETE FROM Likes WHERE post_id = ? AND user_id = ?`;
        db.query(deleteSql, [postId, userId], (err) => {
          if (err) {
            console.error("❌ Like delete error:", err);
            return res.status(500).json({ error: "Like delete error" });
          }

          // Return updated like count
          const countSql = `SELECT COUNT(*) AS count FROM Likes WHERE post_id = ?`;
          db.query(countSql, [postId], (err2, result) => {
            if (err2) {
              console.error("❌ Count error:", err2);
              return res.status(500).json({ error: "Count error" });
            }
            res.json({ liked: false, count: result[0].count });
          });
        });
      }
    });
  });
});

// GET likes for a post, optionally telling if the given username liked it
app.get("/api/post/:id/likes", (req, res) => {
  const { id } = req.params;
  const username = req.query.username || null;

  db.query("SELECT COUNT(*) AS likeCount FROM Likes WHERE post_id = ?", [id], (err, countRes) => {
    if (err) {
      console.error("❌ Error counting likes:", err);
      return res.status(500).json({ message: "Error counting likes" });
    }

    const likeCount = countRes[0]?.likeCount || 0;

    db.query(
      "SELECT username FROM Likes WHERE post_id = ? ORDER BY id DESC LIMIT 3",
      [id],
      (err2, likersRes) => {
        if (err2) {
          console.error("❌ Error fetching likers:", err2);
          return res.status(500).json({ message: "Error fetching likers" });
        }

        const likers = (likersRes || []).map(r => ({ username: r.username }));

        if (username) {
          db.query(
            "SELECT 1 FROM Likes WHERE post_id = ? AND username = ? LIMIT 1",
            [id, username],
            (err3, rows) => {
              if (err3) {
                console.error("❌ Error checking like:", err3);
                return res.status(500).json({ message: "Error checking like" });
              }

              const liked = rows.length > 0;
              return res.json({ likeCount, liked, likers });
            }
          );
        } else {
          return res.json({ likeCount, liked: false, likers });
        }
      }
    );
  });
});

app.post("/api/comment", (req, res) => {
  const { postid, username, comment } = req.body;

  if (!postid || !username || !comment) {
    return res.status(400).json({ message: "Post ID, username and comment required" });
  }

  // Step 1: Insert comment
  const insertComment = "INSERT INTO comments (post_id, username, comment) VALUES (?, ?, ?)";
  db.query(insertComment, [postid, username, comment], (err, result) => {
    if (err) {
      console.error("❌ Error inserting comment:", err);
      return res.status(500).json({ message: "Error adding comment" });
    }

    const commentId = result.insertId;

    // Step 2: Find post owner (from posts table)
    const findOwner = `
      SELECT p.user_id AS ownerId, u.user_id AS commenterId 
      FROM Posts p 
      JOIN Users u ON u.username = ? 
      WHERE p.id = ?
    `;

    db.query(findOwner, [username, postid], (err, rows) => {
      if (err || rows.length === 0) {
        console.error("❌ Error finding post owner:", err);
        return res.status(500).json({ message: "Error finding post owner" });
      }

      const ownerId = rows[0].ownerId;
      const commenterId = rows[0].commenterId;

      // Step 3: Only create notification if commenter ≠ post owner
      if (ownerId !== commenterId) {
        createNotification(commenterId, ownerId, "comment", postid);
      }

      res.json({ 
        message: "Comment added", 
        commentId 
      });
    });
  });
});

app.get("/api/post/comments/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT c.id, c.username, c.comment, c.created_at, u.profile_pic
    FROM comments c
    JOIN Users u ON c.username = u.username
    WHERE c.post_id = ?
    ORDER BY c.created_at DESC
  `;
  db.query(sql, [id], (err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching comments" });
    res.json(results);
  });
});

// API to search users
app.get("/search", (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const sql = `
    SELECT user_id, username, full_name, profile_pic
    FROM Users
    WHERE username LIKE ? OR full_name LIKE ?
    LIMIT 10
  `;
  db.query(sql, [`%${q}%`, `%${q}%`], (err, results) => {
    if (err) {
      console.error("Error searching users:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

app.get("/searchconvo", (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const sql = `
    SELECT user_id, username, full_name, profile_pic
    FROM Users
    WHERE username LIKE ? OR full_name LIKE ?
    LIMIT 10
  `;
  db.query(sql, [`%${q}%`, `%${q}%`], (err, results) => {
    if (err) {
      console.error("Error searching users:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

// Get user profile
app.get("/user/:id", (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.query.currentUserId; // pass logged-in user in query

  const sql = `
    SELECT u.user_id, u.username, u.full_name AS name, u.bio, u.profile_pic,
      (SELECT COUNT(*) FROM followers WHERE following_id = u.user_id) AS followers,
      (SELECT COUNT(*) FROM followers WHERE follower_id = u.user_id) AS following,
      EXISTS(SELECT 1 FROM followers WHERE follower_id = ? AND following_id = u.user_id) AS isFollowed
    FROM Users u
    WHERE u.user_id = ?
  `;

  db.query(sql, [currentUserId, userId], (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(results[0]);
  });
});

// ✅ FOLLOW user
// FOLLOW
app.post("/api/follow", (req, res) => {
  const { follower_id, following_id} = req.body;
  console.log(follower_id, following_id);

  db.query(
    "INSERT INTO followers (follower_id, following_id) VALUES (?, ?)",
    [follower_id, following_id],
    (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).json({ success: false, message: "Already following" });
        }
        return res.status(500).json({ success: false, message: "DB error" });
      }

      // fetch updated follower count
      db.query(
        "SELECT COUNT(*) AS followerCount FROM followers WHERE following_id = ?",
        [following_id],
        (err2, rows) => {
          if (err2) return res.status(500).json({ success: false, message: "DB error" });
          createNotification(follower_id, following_id, "follow");
          res.json({ 
            success: true, 
            message: "Followed successfully", 
            followerCount: rows[0].followerCount 
          });
        
        }
      );
    }
  );
});

// UNFOLLOW
app.delete("/api/follow", (req, res) => {
  const { follower_id, following_id } = req.query; // or req.body depending on your frontend

  db.query(
    "DELETE FROM followers WHERE follower_id = ? AND following_id = ?",
    [follower_id, following_id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });

      // fetch updated follower count
      db.query(
        "SELECT COUNT(*) AS followerCount FROM followers WHERE following_id = ?",
        [following_id],
        (err2, rows) => {
          if (err2) return res.status(500).json({ success: false, message: "DB error" });
          res.json({ 
            success: true, 
            message: "Unfollowed successfully", 
            followerCount: rows[0].followerCount 
          });
        }
      );
    }
  );
});

// ✅ LIKE post
app.post("/api/like", (req, res) => {
  const { user_id, post_id, ownerId } = req.body;
  db.query(
    "INSERT IGNORE INTO Likes (user_id, post_id) VALUES (?, ?)",
    [user_id, post_id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
       createNotification(user_id, ownerId, "like", post_id);
      res.json({ success: true, message: "Liked successfully" });
    }
  );

});

// ✅ UNLIKE
app.delete("/api/like", (req, res) => {
  const { user_id, post_id } = req.body;
  db.query(
    "DELETE FROM Likes WHERE user_id = ? AND post_id = ?",
    [user_id, post_id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
      res.json({ success: true, message: "Unliked successfully" });
    }
  );
});

// ✅ Get like count + whether current user liked
app.get("/api/likes/:postId", (req, res) => {
  const { postId } = req.params;
  const { username } = req.query; // pass ?username=... from frontend

  const sql = `
    SELECT 
      (SELECT COUNT(*) FROM Likes WHERE post_id = ?) AS count,
      EXISTS(
        SELECT 1 FROM Likes WHERE post_id = ? AND username = ?
      ) AS likedByUser
  `;

  db.query(sql, [postId, postId, username], (err, results) => {
    if (err) {
      console.error("❌ Likes query error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results[0]);
  });
});

// ✅ COMMENT on post
app.post("/api/comment", (req, res) => {
  console.log("📥 Received body:", req.body);
  const { postId, username, comment } = req.body;  // use postId not currentPostId

  if (!postId || !username || !comment) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  db.query(
    "INSERT INTO comments (post_id, username, comment, created_at) VALUES (?, ?, ?, NOW())",
    [postId, username, comment],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
      res.json({ success: true, message: "Comment added successfully" });
    }
  );
});

// ✅ GET followers of a user
app.get("/api/users/:username/followers", (req, res) => {
  const { username } = req.params;

  const sql = `
    SELECT u.user_id, u.username, u.full_name, u.profile_pic
    FROM followers f
    JOIN Users u ON u.user_id = f.follower_id
    WHERE f.following_id = (SELECT user_id FROM Users WHERE username = ?)
    ORDER BY u.username ASC
  `;

  db.query(sql, [username], (err, result) => {
    if (err) {
      console.error("Error fetching followers:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(result);
  });
});

// ✅ GET following of a user
app.get("/api/users/:username/following", (req, res) => {
  const { username } = req.params;

  const sql = `
    SELECT u.user_id, u.username, u.full_name, u.profile_pic
    FROM followers f
    JOIN Users u ON u.user_id = f.following_id
    WHERE f.follower_id = (SELECT user_id FROM Users WHERE username = ?)
    ORDER BY u.username ASC
  `;

  db.query(sql, [username], (err, result) => {
    if (err) {
      console.error("Error fetching following:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(result);
  });
});

app.get("/api/suggestion", (req, res) => {
  const { userId, username } = req.query;
  const sql = `
    SELECT 
      u.user_id, 
      u.username, 
      u.full_name, 
      u.profile_pic
    FROM Users u
    WHERE u.username != ?  -- exclude current user
      AND u.user_id NOT IN (   -- exclude already followed users
        SELECT f.following_id 
        FROM followers f 
        WHERE f.follower_id = ?
      )
    ORDER BY RAND()
    LIMIT 5
  `;

  db.query(sql, [username, userId], (err, results) => {
    if (err) {
      console.error("❌ Suggestion error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

// Get all posts for feed
app.get("/api/feed", (req, res) => {
  const { username } = req.query;
  const sql = `
    SELECT 
      p.id, 
      p.content, 
      p.image_url, 
      p.video_url, 
      p.created_at,
      u.username, 
      u.full_name, 
      u.profile_pic,
      (SELECT COUNT(*) FROM Likes l WHERE l.post_id = p.id) AS likes,
      EXISTS(
        SELECT 1 FROM Likes l WHERE l.post_id = p.id AND l.username = ?
      ) AS likedByCurrentUser
    FROM Posts p
    JOIN Users u ON p.username = u.username
    WHERE u.username <> ?   -- exclude current user
    ORDER BY p.created_at DESC
  `;

  db.query(sql, [username, username], (err, results) => {
    if (err) {
      console.error("❌ Feed query error:", err.sqlMessage);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

// API Route to create story
app.post("/api/create-story", upload.single("storyMedia"), (req, res) => {
  const { username } = req.body;

  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded!" });
  }

  const media_url = "/uploads/" + req.file.filename;

  // detect file type by MIME
  const media_type = req.file.mimetype.startsWith("video") ? "video" : "image";

  const sql = `
    INSERT INTO stories (username, media_url, media_type, created_at, expires_at)
    VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR))
  `;

  db.query(sql, [username, media_url, media_type], (err, result) => {
    if (err) {
      console.error("Error inserting story:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.status(200).json({
      message: "Story created successfully ✅",
      storyId: result.insertId,
    });
  });
});

app.get("/api/stories", (req, res) => {
  const sql = `
    SELECT s.id, s.media_url, s.media_type, s.created_at, u.username, u.profile_pic
    FROM stories s
    JOIN Users u ON s.username = u.username
    WHERE s.expires_at > NOW()
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching stories:", err);
      return res.status(500).json({ message: "Database error" });
    }

    // Group stories by username
    const groupedStories = results.reduce((acc, story) => {
      if (!acc[story.username]) {
        acc[story.username] = {
          username: story.username,
          profile_pic: story.profile_pic,
          stories: []
        };
      }
      acc[story.username].stories.push({
        id: story.id,
        media_url: story.media_url,
        media_type: story.media_type,
        created_at: story.created_at
      });
      return acc;
    }, {});

    res.json(Object.values(groupedStories));
  });
});

app.get("/api/notifications/:userId", (req, res) => {
  const { userId } = req.params;

  const sql = `
SELECT 
  n.id,
  n.type,
  n.created_at,
  u.user_id,
  u.username,
  u.profile_pic,
  p.id,
  p.image_url,
  p.video_url
FROM Notifications n
JOIN Users u ON u.user_id = n.sender_id
LEFT JOIN Posts p ON p.id = n.post_id
WHERE n.receiver_id = ?
ORDER BY n.created_at DESC;
  `;

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Notification fetch error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

function createNotification(senderId, receiverId, type, postId = null) {
  const sql = `INSERT INTO Notifications (sender_id, receiver_id, type, post_id) VALUES (?,?,?,?)`;
  db.query(sql, [senderId, receiverId, type, postId], (err) => {
    if (err) console.error("❌ Notification insert error:", err);
  });
}

app.post("/api/conversation", (req, res) => {
  const { user1, user2 } = req.body;

  if (!user1 || !user2) {
    return res.status(400).json({ message: "Missing user IDs" });
  }

  const checkSql = `
    SELECT * FROM Conversations 
    WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
  `;

  db.query(checkSql, [user1, user2, user2, user1], (err, results) => {
    if (err) {
      console.error("Error checking conversation:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length > 0) {
      return res.json(results[0]); // existing conversation
    }

    const insertSql = `
      INSERT INTO Conversations (user1_id, user2_id, created_at) VALUES (?, ?, NOW())
    `;

    db.query(insertSql, [user1, user2], (err, result) => {
      if (err) {
        console.error("Error creating conversation:", err);
        return res.status(500).json({ message: "Database error" });
      }

      res.json({ conversation_id: result.insertId, user1, user2 });
    });
  });
});

app.get("/api/conversations/:userId", (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT 
      c.id AS conversation_id,
      u.user_id,
      u.username,
      u.profile_pic,
      (
        SELECT m.message 
        FROM Messages m 
        WHERE m.conversation_id = c.id 
        ORDER BY m.created_at DESC 
        LIMIT 1
      ) AS last_message,
      (
        SELECT m.created_at 
        FROM Messages m 
        WHERE m.conversation_id = c.id 
        ORDER BY m.created_at DESC 
        LIMIT 1
      ) AS last_time,
      (
        SELECT COUNT(*) 
        FROM Messages m 
        WHERE m.conversation_id = c.id 
          AND m.receiver_id = ? 
          AND m.status != 'seen'
      ) AS unread_count
    FROM Conversations c
    JOIN Users u 
      ON (u.user_id = IF(c.user1_id = ?, c.user2_id, c.user1_id))
    WHERE c.user1_id = ? OR c.user2_id = ?
    ORDER BY last_time DESC
  `;

  db.query(sql, [userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error("❌ Conversation fetch error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

app.post("/api/markAsRead/:conversationId/:userId", (req, res) => {
  const { conversationId, userId } = req.params;

  const sql = `
    UPDATE Messages 
    SET status = 'seen'
    WHERE conversation_id = ? 
      AND receiver_id = ? 
      AND status != 'seen'
  `;

  db.query(sql, [conversationId, userId], (err) => {
    if (err) {
      console.error("❌ Error marking as read:", err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
  });
});

app.get("/api/messages/:conversationId", (req, res) => {
  const { conversationId } = req.params;

  const sql = `
SELECT 
  m.id AS message_id,
  m.sender_id,
  m.receiver_id,
  m.message,
  m.post_id,
  m.created_at,
  m.status,
  p.image_url AS image_url,   -- keep separate
  p.video_url AS video_url,
  u.username AS sender_username,
  u.profile_pic AS sender_profile_pic
FROM Messages m
LEFT JOIN Posts p ON m.post_id = p.id
JOIN Users u ON m.sender_id = u.user_id
WHERE m.conversation_id = ? OR m.post_id = p.id
ORDER BY m.created_at ASC;

  `;

  db.query(sql, [conversationId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching messages:", err);
      return res.status(500).json({ success: false, error: err.message });
    }
console.log("results: ", results);
const formatted = results.map(r => ({
  id: r.message_id,
  sender_id: r.sender_id,
  receiver_id: r.receiver_id,
  message: r.message,
  post_image: r.image_url || null,
  post_video: r.video_url || null,
  status: r.status,
  created_at: r.created_at,
  sender: {
    username: r.sender_username,
    profile_pic: r.sender_profile_pic
  }
}));

console.log("Formatted: ", formatted);
    res.json(formatted);
  });
});

app.post("/api/message", (req, res) => {
  const { conversationId, senderId, receiverId, text } = req.body;
  console.log("📩 Incoming message:", req.body);

  const sql = `
    INSERT INTO Messages (conversation_id, sender_id, receiver_id, message, status, created_at)
    VALUES (?, ?, ?, ?, 'sent', NOW())
  `;

  db.query(sql, [conversationId, senderId, receiverId, text], (err, result) => {
    if (err) {
      console.error("❌ Message insert error:", err);
      return res.status(500).json({ success: false, error: err.message });
    }

    res.json({ success: true, message_id: result.insertId });
  });
});

// Mark as delivered (when receiver opens chat)
app.put("/api/message/delivered/:conversationId/:receiverId", (req, res) => {
  const { conversationId, receiverId } = req.params;
  const sql = `
    UPDATE Messages 
    SET status = 'delivered' 
    WHERE conversation_id = ? AND receiver_id = ? AND status = 'sent'
  `;
  db.query(sql, [conversationId, receiverId], err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Mark as seen (when receiver reads messages)
app.put("/api/message/seen/:conversationId/:receiverId", (req, res) => {
  const { conversationId, receiverId } = req.params;
  const sql = `
    UPDATE Messages 
    SET status = 'seen' 
    WHERE conversation_id = ? AND receiver_id = ? AND status != 'seen'
  `;
  db.query(sql, [conversationId, receiverId], err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Find user by username
app.get("/api/findUser/:username", (req, res) => {
  const { username } = req.params;

  const sql = `
    SELECT user_id, username, full_name, profile_pic 
    FROM Users 
    WHERE username LIKE ?
  `;

  // Wrap the username with % for LIKE search
  db.query(sql, [`%${username}%`], (err, results) => {
    if (err) {
      console.error("❌ Error finding user:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (results.length === 0) {
      return res.json(null); // user not found
    }

    res.json(results[0]); // return found user
  });
});

app.post("/api/share", (req, res) => {
  const { postId, senderId, receivers } = req.body;

  console.log(req.body);
  console.log(postId, senderId, receivers);
  if (!postId || !senderId || !receivers || receivers.length === 0) {
    return res.status(400).json({ error: "Missing data" });
  }

  // Insert message for each selected user
  const sql = `
    INSERT INTO Messages (sender_id, receiver_id, message, post_id, created_at)
    VALUES ?
  `;

  // Bulk insert values
  const values = receivers.map(rid => [senderId, rid, "shared a reel with you", postId, new Date()]);

  db.query(sql, [values], (err, result) => {
    if (err) {
      console.error("❌ Share insert error:", err);
      return res.status(500).json({ error: "Failed to share reel" });
    }

    res.json({ success: true, sharedCount: receivers.length });
  });
});

// Start server
app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});