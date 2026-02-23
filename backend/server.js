const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.BACKEND_PORT || 3000;

// PostgreSQL pool for appdb
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'appdb',
  user: process.env.DB_USER || 'keycloak',
  password: process.env.DB_PASSWORD || 'password'
});

// Keycloak Configuration
// Internal URL: used by backend container to talk to Keycloak inside Docker
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://keycloak:8080';
// Public URL: used by browser and appears as token issuer
const KEYCLOAK_PUBLIC_URL = process.env.KEYCLOAK_PUBLIC_URL || 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'myrealm';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'my-app';
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || 'your-client-secret';

// JWKS Client - uses INTERNAL URL to fetch keys (backend runs inside Docker)
const client = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`
});

// Middleware
app.use(cors({
  origin: ['http://localhost:8000', 'http://127.0.0.1:8000', 'http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Helper function to get signing key
function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
      console.error('JWKS key fetch error:', err.message);
      callback(err);
      return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Middleware to verify JWT token - NO audience check (Keycloak uses 'account' not client ID)
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);

  // First try to decode without verification to see the token
  const decoded = jwt.decode(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token format' });
  }

  console.log('Token issuer:', decoded.iss);
  console.log('Token audience:', decoded.aud);

  jwt.verify(token, getKey, {
    algorithms: ['RS256']
  }, (err, verified) => {
    if (err) {
      console.error('JWT verify error:', err.message);
      return res.status(401).json({ error: 'Invalid token', details: err.message });
    }
    req.user = verified;
    next();
  });
};

// Delete all emails from MailHog on logout
async function deleteMailHogEmails() {
  try {
    const MAILHOG_API = process.env.MAILHOG_API || 'http://mailhog:8025';
    await axios.delete(`${MAILHOG_API}/api/v1/messages`);
    console.log('All MailHog emails deleted');
  } catch (error) {
    console.error('Error deleting MailHog emails:', error.message);
  }
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend is running' });
});

// Get Keycloak configuration (PUBLIC URLs for the browser)
app.get('/api/auth/config', (req, res) => {
  res.json({
    keycloakUrl: KEYCLOAK_PUBLIC_URL,
    realm: KEYCLOAK_REALM,
    clientId: KEYCLOAK_CLIENT_ID,
    authUrl: `${KEYCLOAK_PUBLIC_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth`,
    tokenUrl: `${KEYCLOAK_PUBLIC_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
    logoutUrl: `${KEYCLOAK_PUBLIC_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout`,
    registerUrl: `${KEYCLOAK_PUBLIC_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/registrations`
  });
});

// Exchange authorization code for tokens (backend talks to Keycloak INTERNALLY)
app.post('/api/auth/token', async (req, res) => {
  const { code, redirectUri } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Authorization code is required' });
  }

  console.log('Exchanging code for tokens...');
  console.log('Redirect URI:', redirectUri);

  try {
    const tokenResponse = await axios.post(
      `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
        code: code,
        redirect_uri: redirectUri || 'http://localhost:8000/callback'
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token, id_token } = tokenResponse.data;

    console.log('Token exchange successful!');

    const decoded = jwt.decode(access_token);
    console.log('Decoded token user:', decoded?.name, decoded?.email);

    res.json({
      accessToken: access_token,
      refreshToken: refresh_token,
      idToken: id_token,
      expiresIn: tokenResponse.data.expires_in
    });
  } catch (error) {
    console.error('Token exchange error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to exchange authorization code', 
      details: error.response?.data || error.message 
    });
  }
});

// Initialize contacts table (address book)
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(50),
        address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // Add user_id to existing table if missing
    await pool.query(`
      ALTER TABLE contacts ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
    `).catch(() => {});
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_contacts_user_name ON contacts (user_id, name)
    `);
    console.log('Contacts table ready');
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

// Address Book API - all endpoints require JWT

// GET /api/contacts - list contacts for logged-in user only
app.get('/api/contacts', verifyToken, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { rows } = await pool.query(
      'SELECT id, name, email, phone, address, created_at, updated_at FROM contacts WHERE user_id = $1 ORDER BY name ASC',
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Contacts fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

// GET /api/contacts/:id - get single contact (own contacts only)
app.get('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.sub;
    const { rows } = await pool.query(
      'SELECT id, name, email, phone, address, created_at, updated_at FROM contacts WHERE id = $1 AND user_id = $2',
      [id, userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Contact not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Contact fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch contact' });
  }
});

// POST /api/contacts - create contact (tied to logged-in user)
app.post('/api/contacts', verifyToken, async (req, res) => {
  try {
    const { name, email, phone, address } = req.body;
    const userId = req.user.sub;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const { rows } = await pool.query(
      'INSERT INTO contacts (user_id, name, email, phone, address) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, phone, address, created_at, updated_at',
      [userId, name, email || null, phone || null, address || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Contact create error:', err.message);
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

// PUT /api/contacts/:id - update contact (own contacts only)
app.put('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, address } = req.body;
    const userId = req.user.sub;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const { rows } = await pool.query(
      'UPDATE contacts SET name = $1, email = $2, phone = $3, address = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 AND user_id = $6 RETURNING id, name, email, phone, address, created_at, updated_at',
      [name, email || null, phone || null, address || null, id, userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Contact not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Contact update error:', err.message);
    res.status(500).json({ error: 'Failed to update contact' });
  }
});

// DELETE /api/contacts/:id - delete contact (own contacts only)
app.delete('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.sub;
    const { rowCount } = await pool.query('DELETE FROM contacts WHERE id = $1 AND user_id = $2', [id, userId]);
    if (rowCount === 0) return res.status(404).json({ error: 'Contact not found' });
    res.json({ message: 'Contact deleted' });
  } catch (err) {
    console.error('Contact delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// Get user profile (protected route)
app.get('/api/user/profile', verifyToken, (req, res) => {
  console.log('Profile request for user:', req.user.preferred_username);
  res.json({
    id: req.user.sub,
    name: req.user.name || req.user.preferred_username,
    email: req.user.email,
    username: req.user.preferred_username,
    emailVerified: req.user.email_verified
  });
});

// Logout endpoint
app.post('/api/auth/logout', verifyToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    const userEmail = req.user.email;
    const userName = req.user.name || req.user.preferred_username;

    // Revoke the refresh token in Keycloak
    if (refreshToken) {
      try {
        await axios.post(
          `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout`,
          new URLSearchParams({
            client_id: KEYCLOAK_CLIENT_ID,
            client_secret: KEYCLOAK_CLIENT_SECRET,
            refresh_token: refreshToken
          }),
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          }
        );
      } catch (logoutErr) {
        console.error('Keycloak logout error:', logoutErr.response?.data || logoutErr.message);
      }
    }

    // Delete all emails from MailHog on logout
    await deleteMailHogEmails();

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Logout failed', 
      details: error.response?.data || error.message 
    });
  }
});

// Refresh token endpoint
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const tokenResponse = await axios.post(
      `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
        refresh_token: refreshToken
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    res.json({
      accessToken: tokenResponse.data.access_token,
      refreshToken: tokenResponse.data.refresh_token,
      expiresIn: tokenResponse.data.expires_in
    });
  } catch (error) {
    console.error('Token refresh error:', error.response?.data || error.message);
    res.status(401).json({ 
      error: 'Failed to refresh token', 
      details: error.response?.data || error.message 
    });
  }
});

// Start server
app.listen(PORT, async () => {
  await initDb();
  console.log(`Backend server running on port ${PORT}`);
  console.log(`Keycloak Internal URL: ${KEYCLOAK_URL}`);
  console.log(`Keycloak Public URL: ${KEYCLOAK_PUBLIC_URL}`);
  console.log(`Realm: ${KEYCLOAK_REALM}`);
  console.log(`Client ID: ${KEYCLOAK_CLIENT_ID}`);
});
