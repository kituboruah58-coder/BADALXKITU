# CLOUD X STREAMER - Streamer Dashboard

A complete, production-ready streamer authentication and management system built with Node.js, Express, SQLite, and a modern vanilla JavaScript frontend.

## Features

✅ **User Registration** - Create new accounts with password strength validation
✅ **User Login** - Secure authentication with JWT tokens
✅ **License Key Registration** - Activate accounts with license keys
✅ **Password Hashing** - bcrypt for secure password storage
✅ **JWT Tokens** - Stateless authentication system
✅ **SQLite Database** - Persistent data storage
✅ **CORS Support** - Cross-origin request handling
✅ **Responsive UI** - Mobile-friendly design
✅ **Session Management** - Token-based session tracking
✅ **Dashboard** - User profile and activity dashboard

## Project Structure

```
├── backend/
│   ├── server.js           # Express server setup
│   ├── database.js         # SQLite database initialization
│   ├── auth.js             # Authentication logic
│   └── auth.db             # SQLite database file (created on first run)
├── frontend/
│   ├── index.html          # Login/Register/License page
│   └── dashboard.html      # User dashboard
├── package.json            # NPM dependencies
├── .env                    # Environment variables
└── README.md              # This file
```

## Installation

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Setup

1. **Install dependencies:**
```bash
npm install
```

2. **Start the server:**
```bash
npm start
```

The application will start on `http://localhost:5000`

## Usage

### Login Page
Access the login page at `http://localhost:5000`

**Test Credentials:**
- Email: `test@example.com`
- Password: `password123`

Or create a new account using the Register tab.

### License Registration
Use the test license key: `TEST-1234-5678-ABCD`

### API Endpoints

#### Register
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123",
  "confirm": "securepassword123"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

#### License Registration
```bash
POST /api/auth/license
Content-Type: application/json

{
  "license": "TEST-1234-5678-ABCD",
  "email": "john@example.com",
  "password": "securepassword123",
  "confirm": "securepassword123"
}
```

#### Get Current User
```bash
GET /api/auth/me
Authorization: Bearer <token>
```

#### Health Check
```bash
GET /api/health
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Licenses Table
```sql
CREATE TABLE licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key TEXT UNIQUE NOT NULL,
  user_id INTEGER,
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Security Features

🔐 **Password Hashing** - bcryptjs with salt rounds
🔐 **JWT Authentication** - Stateless token-based auth
🔐 **CORS Protection** - Configurable cross-origin access
🔐 **SQL Injection Prevention** - Parameterized queries
🔐 **Input Validation** - Email and password validation
🔐 **Expiring Tokens** - 7-day token expiration
🔐 **Session Tracking** - Server-side session logging

## Environment Variables

Edit `.env` file to configure:

```
PORT=5000                    # Server port
JWT_SECRET=your-secret-key   # JWT signing key
NODE_ENV=development         # Environment mode
```

⚠️ **Important:** Change `JWT_SECRET` in production!

## Development

### Running in Development Mode
```bash
npm run dev
```

### Creating Test Licenses
To add test license keys, run this in the backend:

```javascript
const db = require('./backend/database');

db.run(`
  INSERT INTO licenses (license_key, status) 
  VALUES ('TEST-1234-5678-ABCD', 'active')
`);
```

## Troubleshooting

### Port Already in Use
```bash
# Change port in .env
PORT=3000
```

### Database Issues
Delete `backend/auth.db` to reset the database. It will be recreated on next start.

### CORS Errors
Ensure frontend and backend are running on correct ports (frontend serves via port 5000).

## Future Enhancements

- [ ] Email verification for new accounts
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] OAuth integration (Google, GitHub, Discord)
- [ ] User profile management
- [ ] Activity logging and analytics
- [ ] Admin dashboard
- [ ] Rate limiting and brute-force protection
- [ ] Refresh token rotation
- [ ] Account recovery options

## License

MIT License - Feel free to use this project for personal or commercial purposes.

## Support

For issues or questions, please check the troubleshooting section or create an issue in the repository.

---

**Built with ❤️ using Node.js, Express, and SQLite**
