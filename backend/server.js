const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const session = require('express-session');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.BACKEND_PORT || 3000;

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

// MailHog Configuration
const mailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'mailhog',
  port: process.env.SMTP_PORT || 1025,
  secure: false,
  tls: {
    rejectUnauthorized: false
  }
});

// Middleware
app.use(cors({
  origin: ['http://localhost:8000', 'http://127.0.0.1:8000'],
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

// Send welcome email
async function sendWelcomeEmail(email, name) {
  try {
    await mailTransporter.sendMail({
      from: '"My App" <noreply@myapp.com>',
      to: email,
      subject: 'Welcome to My App!',
      html: `
        <h1>Welcome, ${name}!</h1>
        <p>You have successfully registered and logged in to My App.</p>
        <p>This email was sent to verify the email functionality.</p>
      `
    });
    console.log(`Welcome email sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

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

    // Decode the token to get user info
    const decoded = jwt.decode(access_token);
    console.log('Decoded token user:', decoded?.name, decoded?.email);
    
    // Send welcome email
    if (decoded && decoded.email) {
      await sendWelcomeEmail(decoded.email, decoded.name || decoded.preferred_username);
    }

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
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log(`Keycloak Internal URL: ${KEYCLOAK_URL}`);
  console.log(`Keycloak Public URL: ${KEYCLOAK_PUBLIC_URL}`);
  console.log(`Realm: ${KEYCLOAK_REALM}`);
  console.log(`Client ID: ${KEYCLOAK_CLIENT_ID}`);
});
