import express from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import Sequelize from "sequelize";


dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

console.log("DATABASE_URL:", process.env.DATABASE_URL);

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: "mysql",
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  }
});

sequelize.authenticate()
  .then(() => console.log("Connected to Railway MySQL!"))
  .catch(err => console.error("Database connection failed:", err));

const checkBlockedUser = (req, res, next) => {
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ message: "User ID missing in request." });
  }
  db.query("SELECT isBlocked FROM users WHERE id = ?", [userId], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length === 0) {
      console.error("User ID not found in database:", userId);
      return res.status(404).json({ message: "User not found." });
    }
    if (result[0].isBlocked) {
      console.error("User is blocked:", userId);
      return res.status(403).json({ message: "Your account is blocked. Redirecting to login." });
    }
    next();
  });
};

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Email and Password required" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
    [name, email, hashedPassword],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "User registered successfully!" });
    }
  );
});

app.get("/users", async (req, res) => {
  db.query("SELECT id, name, email, last_seen, isBlocked FROM users", (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    const formattedUsers = results.map(user => {
      const formattedTimestamp = user.last_seen ? new Date(user.last_seen).toISOString() : null;
      return {
        ...user,
        last_seen: formattedTimestamp,
        isBlocked: user.isBlocked,
      };
    });
    res.json(formattedUsers);
  });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password required" });
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }
    const user = result[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }
     if (user.isBlocked) {
      return res.status(403).json({ message: "Your account is blocked." });
    }
    db.query("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);
    res.json({ message: "Login successful!", userId: user.id, name: user.name });
  });
});

app.delete("/delete-users", checkBlockedUser, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) {
    console.error("No user IDs provided for deletion.");
    return res.status(400).json({ message: "No users selected for deletion" });
  }
  try {
    await db.promise().query("DELETE FROM users WHERE id IN (?)", [userIds]);
    res.json({ message: "Users deleted successfully" });
  } catch (error) {
    console.error("Error deleting users from database:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/block-users", checkBlockedUser, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) {
    return res.status(400).json({ message: "No users selected for blocking" });
  }
  try {
    console.log("Blocking users with IDs:", userIds);
    await db.promise().query("UPDATE users SET isBlocked = TRUE WHERE id IN (?)", [userIds]);
    res.json({ message: "Users blocked successfully" });
  } catch (error) {
    console.error("Error blocking users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/unblock-users", checkBlockedUser, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) {
    return res.status(400).json({ message: "No users selected for unblocking" });
  }
  try {
    await db.promise().query("UPDATE users SET isBlocked = FALSE WHERE id IN (?)", [userIds]);
    res.json({ message: "Users unblocked successfully" });
  } catch (error) {
    console.error("Error unblocking users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const PORT = process.env.PORT || 3306;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));