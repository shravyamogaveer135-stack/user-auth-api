const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors()); 
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_change_in_production';

// Persistent file-based SQLite database configuration
const dbPath = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Initialize Users table automatically on application startup
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Users table verified/created successfully.');
    }
  });
});

// Middleware: JWT Authentication Guard for Protected Routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// Root endpoint
app.get('/', (req, res) => {
  res.json({ message: 'User Authentication System API is running with SQLite' });
});

// 1. REGISTER Endpoint (/auth/register)
app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  // Form validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields (username, email, password) are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;

    db.run(sql, [username, email, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username or email already exists' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ 
        message: 'User registered successfully', 
        userId: this.lastID 
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// 2. LOGIN Endpoint (/auth/login)
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  // Form validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const sql = `SELECT * FROM users WHERE email = ?`;
  db.get(sql, [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Generate JWT Token
      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email }, 
        JWT_SECRET, 
        { expiresIn: '1h' }
      );

      res.json({ 
        message: 'Login successful', 
        token 
      });
    } catch (compareError) {
      res.status(500).json({ error: 'Server error during authentication' });
    }
  });
});

// 3. PASSWORD RESET Endpoint (/auth/reset-password)
app.post('/auth/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  // Form validation
  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Email and new password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const sql = `UPDATE users SET password = ? WHERE email = ?`;

    db.run(sql, [hashedPassword, email], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ message: 'Password updated successfully' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// 4. PROTECTED PROFILE ROUTE (/auth/profile)
app.get('/auth/profile', authenticateToken, (req, res) => {
  res.json({
    message: 'Welcome to your protected profile area!',
    user: req.user
  });
});

// 5. LOGOUT Endpoint (/auth/logout)
app.post('/auth/logout', (req, res) => {
  res.json({ message: 'Logged out successfully. Please clear your token on the client side.' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running smoothly on port ${PORT}`);
});