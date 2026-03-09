require('dotenv').config();

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

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

let auth0PublicKey = '';
axios.get(`https://${AUTH0_DOMAIN}/pem`)
    .then(response => {
        auth0PublicKey = response.data;
        console.log("Public PEM key successfully fetched from Auth0.");
    })
    .catch(err => {
        console.error("Error fetching PEM key:", err.message);
    });

if (!process.env.ENCRYPTION_KEY) {
    throw new Error("Missing ENCRYPTION_KEY in .env file! Generate a 32-byte hex string.");
}

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16;

function encryptToken(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptToken(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
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

        const encryptedAccessToken = encryptToken(response.data.access_token);

        res.json({
            ...response.data,
            access_token: encryptedAccessToken
        });
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

        const encryptedAccessToken = encryptToken(response.data.access_token);

        res.json({
            ...response.data,
            access_token: encryptedAccessToken
        });
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

    const encryptedToken = authHeader.replace('Bearer ', '').trim();
    let originalToken;

    try {
        originalToken = decryptToken(encryptedToken);
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return res.status(401).json({ error: 'Invalid encrypted token format' });
    }

    jwt.verify(originalToken, auth0PublicKey, {
        audience: AUTH0_AUDIENCE,
        issuer: `https://${AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err.message);
            return res.status(401).json({ error: 'Invalid token signature' });
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