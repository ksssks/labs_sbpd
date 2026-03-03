require('dotenv').config();

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const {
    AUTH0_DOMAIN,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    AUTH0_AUDIENCE,
    PORT
} = process.env;


const jwks = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5
});

function getKey(header, callback) {
    console.log("Fetching signing key. KID:", header.kid);
    jwks.getSigningKey(header.kid, function (err, key) {
        if (err) {
            console.error("Error fetching signing key:", err);
            return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}


app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    console.log("Login attempt:", login);

    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            {
                grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
                username: login,
                password: password,
                audience: AUTH0_AUDIENCE,
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                scope: 'openid profile offline_access',
                realm: 'Username-Password-Authentication'
            },
            { headers: { 'content-type': 'application/json' } }
        );
        console.log("Login successful:", login);
        res.json(response.data);
    } catch (err) {
        console.error("AUTH0 LOGIN ERROR:", err.response?.data || err.message);
        res.status(401).json({ error: 'Wrong email or password' });
    }
});

app.post('/api/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    console.log("Refresh token request");

    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            {
                grant_type: 'refresh_token',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                refresh_token
            },
            { headers: { 'content-type': 'application/json' } }
        );
        console.log("Token refreshed successfully");
        res.json(response.data);
    } catch (err) {
        console.error("REFRESH ERROR:", err.response?.data || err.message);
        res.status(401).json({ error: 'Refresh failed' });
    }
});

app.get('/api/profile', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.warn("No Authorization header");
        return res.status(401).json({ error: 'No token' });
    }

    const token = authHeader.replace('Bearer ', '');
    jwt.verify(token, getKey, {
        audience: AUTH0_AUDIENCE,
        issuer: `https://${AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err.message);
            return res.status(401).json({ error: 'Invalid token' });
        }

        const expTime = decoded.exp * 1000;
        const now = Date.now();
        const timeLeft = expTime - now;
        console.log("Token expires in ms:", timeLeft);

        if (timeLeft < 60000) return res.status(401).json({ error: 'Token expiring soon', needRefresh: true });

        console.log("Token valid for user:", decoded.sub);
        res.json({ message: 'Token valid', user: decoded });
    });
});

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    console.log("Register attempt:", email);

    try {
        const mgmtToken = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            {
                grant_type: 'client_credentials',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                audience: `https://${AUTH0_DOMAIN}/api/v2/`
            }
        );

        const accessToken = mgmtToken.data.access_token;
        console.log("Management token received");

        const newUser = await axios.post(
            `https://${AUTH0_DOMAIN}/api/v2/users`,
            { email, password, connection: 'Username-Password-Authentication' },
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        console.log("User created:", newUser.data.user_id);
        res.json(newUser.data);

    } catch (err) {
        console.error("USER CREATION ERROR:", err.response?.data || err.message);
        res.status(400).json({ error: err.response?.data || 'User creation failed' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));