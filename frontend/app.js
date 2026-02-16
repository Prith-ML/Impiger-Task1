// Configuration
const BACKEND_URL = 'http://localhost:3000';
const REDIRECT_URI = window.location.origin + '/callback';

// DOM Elements
const loginSection = document.getElementById('login-section');
const dashboardSection = document.getElementById('dashboard-section');
const loadingSection = document.getElementById('loading-section');
const errorSection = document.getElementById('error-section');

const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const logoutBtn = document.getElementById('logout-btn');
const retryBtn = document.getElementById('retry-btn');

const userName = document.getElementById('user-name');
const userEmail = document.getElementById('user-email');
const userUsername = document.getElementById('user-username');
const userInitial = document.getElementById('user-initial');
const errorMessage = document.getElementById('error-message');

// State
let authConfig = null;

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
    console.log('App initialized');
    
    // Check for auth error
    const authError = localStorage.getItem('auth_error');
    if (authError) {
        showError(authError);
        localStorage.removeItem('auth_error');
        return;
    }

    // Check if user is already logged in
    const accessToken = localStorage.getItem('access_token');
    
    if (accessToken) {
        await loadUserProfile();
    } else {
        showSection('login');
    }

    // Load auth configuration
    await loadAuthConfig();
});

// Load Keycloak configuration from backend
async function loadAuthConfig() {
    try {
        const response = await fetch(`${BACKEND_URL}/api/auth/config`);
        authConfig = await response.json();
        console.log('Auth config loaded:', authConfig);
    } catch (error) {
        console.error('Failed to load auth config:', error);
        showError('Failed to load authentication configuration');
    }
}

// Event Listeners
loginBtn.addEventListener('click', initiateLogin);
registerBtn.addEventListener('click', initiateRegister);
logoutBtn.addEventListener('click', logout);
retryBtn.addEventListener('click', () => {
    showSection('login');
});

// Initiate OAuth 2.0 login flow
async function initiateLogin() {
    if (!authConfig) {
        await loadAuthConfig();
        if (!authConfig) {
            showError('Authentication configuration not available');
            return;
        }
    }

    // Generate random state for CSRF protection
    const state = generateRandomString(32);
    localStorage.setItem('oauth_state', state);

    // Build authorization URL
    const authUrl = new URL(authConfig.authUrl);
    authUrl.searchParams.append('client_id', authConfig.clientId);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'openid profile email');
    authUrl.searchParams.append('state', state);

    console.log('Redirecting to:', authUrl.toString());
    
    // Redirect to Keycloak login page
    window.location.href = authUrl.toString();
}

// Initiate registration flow (Keycloak registration page)
async function initiateRegister() {
    if (!authConfig) {
        await loadAuthConfig();
        if (!authConfig) {
            showError('Authentication configuration not available');
            return;
        }
    }

    const state = generateRandomString(32);
    localStorage.setItem('oauth_state', state);

    // Use Keycloak's registration endpoint
    const registerUrl = new URL(authConfig.authUrl);
    registerUrl.searchParams.append('client_id', authConfig.clientId);
    registerUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    registerUrl.searchParams.append('response_type', 'code');
    registerUrl.searchParams.append('scope', 'openid profile email');
    registerUrl.searchParams.append('state', state);
    registerUrl.searchParams.append('kc_action', 'register');

    window.location.href = registerUrl.toString();
}

// Load user profile
async function loadUserProfile() {
    showSection('loading');

    const accessToken = localStorage.getItem('access_token');

    try {
        const response = await fetch(`${BACKEND_URL}/api/user/profile`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch user profile');
        }

        const user = await response.json();
        displayUserProfile(user);
    } catch (error) {
        console.error('Error loading profile:', error);
        
        // Try to refresh token
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
            try {
                await refreshAccessToken();
                await loadUserProfile();
                return;
            } catch (refreshError) {
                console.error('Token refresh failed:', refreshError);
            }
        }
        
        // Clear tokens and show login
        clearTokens();
        showError('Session expired. Please login again.');
    }
}

// Display user profile
function displayUserProfile(user) {
    userName.textContent = user.name || user.username;
    userEmail.textContent = user.email;
    userUsername.textContent = `@${user.username}`;
    
    // Set initial
    const initial = (user.name || user.username || 'U').charAt(0).toUpperCase();
    userInitial.textContent = initial;

    showSection('dashboard');
}

// Logout
async function logout() {
    showSection('loading');

    const accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');

    try {
        // Call backend logout endpoint
        await fetch(`${BACKEND_URL}/api/auth/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ refreshToken })
        });

        console.log('Logout successful');
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Clear local storage regardless
        clearTokens();
        showSection('login');
    }
}

// Refresh access token
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refresh_token');

    if (!refreshToken) {
        throw new Error('No refresh token available');
    }

    const response = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ refreshToken })
    });

    if (!response.ok) {
        throw new Error('Token refresh failed');
    }

    const data = await response.json();
    localStorage.setItem('access_token', data.accessToken);
    localStorage.setItem('refresh_token', data.refreshToken);

    return data.accessToken;
}

// Utility functions
function showSection(section) {
    loginSection.classList.add('hidden');
    dashboardSection.classList.add('hidden');
    loadingSection.classList.add('hidden');
    errorSection.classList.add('hidden');

    switch(section) {
        case 'login':
            loginSection.classList.remove('hidden');
            break;
        case 'dashboard':
            dashboardSection.classList.remove('hidden');
            break;
        case 'loading':
            loadingSection.classList.remove('hidden');
            break;
        case 'error':
            errorSection.classList.remove('hidden');
            break;
    }
}

function showError(message) {
    errorMessage.textContent = message;
    showSection('error');
}

function clearTokens() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('oauth_state');
}

function generateRandomString(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    
    for (let i = 0; i < length; i++) {
        result += charset[randomValues[i] % charset.length];
    }
    
    return result;
}

// Decode JWT token (for debugging)
function decodeJWT(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('Error decoding JWT:', error);
        return null;
    }
}
