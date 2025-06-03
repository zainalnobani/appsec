const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const xssClean = require('xss-clean');
const cors = require('cors');

dotenv.config();
const app = express();

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ Mongo Error:', err));

// ✅ Mongoose User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// ✅ AES Encryption
const AES_KEY = Buffer.from(process.env.AES_KEY, 'hex');
const AES_IV = Buffer.from(process.env.AES_IV, 'hex');

function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, AES_IV);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encrypted) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, AES_IV);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ✅ Output Sanitization Function
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, match => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[match]));
}

// ✅ Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(xssClean());
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  }
}));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600000
  }
}));

// ✅ Rate Limiting on login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: '❌ Too many login attempts. Please try again later.'
});
app.use('/login', loginLimiter);

// ✅ Registration
app.post('/register',
  body('name').trim().escape().isLength({ min: 2 }),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    let { name, email, password } = req.body;
    const encryptedEmail = encrypt(email);
    const hash = await bcrypt.hash(password, 12);

    try {
      const newUser = new User({ name, email: encryptedEmail, password: hash });
      await newUser.save();
      req.session.regenerate(() => {
        req.session.userId = newUser._id;
        res.status(201).json({ message: 'Registered successfully' });
      });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ error: 'Email already exists' });
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ✅ Login
app.post('/login',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const users = await User.find();
    const user = users.find(u => decrypt(u.email) === email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    req.session.regenerate(() => {
      req.session.userId = user._id;
      res.json({ message: 'Login successful' });
    });
  }
);

// ✅ Middlewares
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).send('Unauthorized');
  next();
}

function requireAdmin(req, res, next) {
  User.findById(req.session.userId).then(user => {
    if (!user || user.role !== 'admin') return res.status(403).send('Admins only');
    next();
  }).catch(() => res.status(500).send('Error checking admin'));
}

// ✅ Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  if (!user) return res.status(404).send('User not found');
  res.send(`
    <h1>Welcome, ${escapeHTML(user.name)}</h1>
    <p>Your role: ${escapeHTML(user.role)}</p>
    <a href="/logout">Logout</a><br>
    ${user.role === 'admin' ? '<a href="/admin-panel">Go to Admin Panel</a>' : ''}
  `);
});

// ✅ Admin Panel
app.get('/admin-panel', requireAdmin, async (req, res) => {
  try {
    const users = await User.find();
    let table = `<h1>Admin Panel</h1><table border="1"><tr><th>Name</th><th>Email</th><th>Role</th><th>Action</th></tr>`;
    users.forEach(user => {
      const email = decrypt(user.email);
      table += `
        <tr>
          <td>${escapeHTML(user.name)}</td>
          <td>${escapeHTML(email)}</td>
          <td>${escapeHTML(user.role)}</td>
          <td>
            <form method="POST" action="/delete-user" style="display:inline;">
              <input type="hidden" name="id" value="${user._id}">
              <button type="submit">Delete</button>
            </form>
          </td>
        </tr>`;
    });
    table += `</table><br><a href="/dashboard">Back</a>`;
    res.send(table);
  } catch {
    res.status(500).send('Error loading admin panel');
  }
});

// ✅ Delete user
app.post('/delete-user', express.urlencoded({ extended: false }), requireAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.body.id);
    res.redirect('/admin-panel');
  } catch {
    res.status(500).send('Failed to delete user');
  }
});

// ✅ Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// ✅ Home
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// ✅ Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
