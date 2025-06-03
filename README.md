# appsec

# Secure Authentication Web App

This project is a secure web application built using **Node.js**, **Express**, and **MongoDB**, featuring:

- Secure user registration and login
- AES-256 encryption of sensitive data (email)
- Password hashing with bcrypt
- Admin panel for managing users
- Session handling with role-based access control
- Security headers, XSS protection, and rate limiting

---

 Pages

| Page            | Purpose                                      |
|-----------------|----------------------------------------------|
| `register.html` | For new users to create an account           |
| `login.html`    | For existing users to log in                 |
| `/dashboard`    | Displays user role and a welcome message     |
| `/admin-panel`  | Admin-only page to view and manage all users |

---

##  Project Components

| File/Folder           | Description                          |
|-----------------------|--------------------------------------|
| `public/login.html`   | Login form UI                        |
| `public/register.html`| Registration form UI                 |
| `server.js`           | Main backend logic (Express server)  |
| `models/User.js`      | MongoDB user schema using Mongoose   |
| `.env`                | Environment variables (private)      |
| `.gitignore`          | Files/folders excluded from Git      |

---

## ⚙️ How It Works

1. User visits `register.html` or `login.html`.
2. The form is submitted using JavaScript's `fetch()` API.
3. The server:
   - Validates and sanitizes user input
   - Encrypts the email address using AES-256
   - Hashes the password using bcrypt
   - Stores the user in MongoDB
4. On login:
   - The session is created
   - The user’s role (admin or user) is checked
   - Admins are granted access to the admin panel

---

## 🧪 Technologies Used

**Frontend**:
- HTML
- JavaScript (Vanilla, with Fetch API)

**Backend**:
- Node.js
- Express.js

**Database**:
- MongoDB (via Mongoose)

**Security Libraries**:
- `bcrypt` – Password hashing
- `crypto` – AES-256 encryption
- `express-session` – Session handling
- `express-validator` – Input validation
- `xss-clean` – Output sanitization
- `helmet` – Security headers (CSP, etc.)
- `express-rate-limit` – Prevents brute-force attacks

---

##  Security Features

| Feature               | Description                                   |
|-----------------------|-----------------------------------------------|
| **Input Validation**  | Blocks dangerous or invalid user input        |
| **Output Sanitization** | Prevents XSS attacks                         |
| **Session Management**| Manages user sessions securely                |
| **Role-based Access** | Distinguishes between admin and regular users |
| **Encrypted Emails**  | AES-256-CBC encryption of email addresses     |
| **Rate Limiting**     | Prevents brute-force login attempts           |

---
###  Security Scanning Result

We used **Snyk CLI** to perform a vulnerability scan on our Node.js + MongoDB application.  
After cleaning unused dependencies, the scan reported:

>  104 dependencies tested — **No known vulnerabilities or risky paths** detected.

This confirms the integrity and security of all included packages as of the scan date.

 Usage
Clone the repository.

Run:

npm install

Add .env with your values.

Start the app:


node server.js
Open in browser:

http://localhost:3001/login.html
