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

const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const LOGOUT_RETURN_URL = `http://localhost:${PORT}`;

// Отримання публічного ключа Auth0
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

app.get('/login', (req, res) => {
    const auth0Url = `https://${AUTH0_DOMAIN}/authorize?` + new URLSearchParams({
        client_id: AUTH0_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        response_mode: 'query',
        audience: AUTH0_AUDIENCE,
        scope: 'openid profile email offline_access'
    }).toString();

    res.redirect(auth0Url);
});

app.get('/callback', async (req, res) => {
    const { code, error, error_description } = req.query;

    if (error) {
        console.error("Auth0 Callback Error:", error_description);
        return res.status(401).send(`Authentication failed: ${error_description}`);
    }

    if (!code) {
        return res.status(400).send("Authorization code is missing.");
    }

    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            {
                grant_type: 'authorization_code',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI
            },
            { headers: { 'content-type': 'application/json' } }
        );

        const encryptedAccessToken = encryptToken(response.data.access_token);
        res.redirect(`/?token=${encryptedAccessToken}`);

    } catch (err) {
        console.error("TOKEN EXCHANGE ERROR:", err.response?.data || err.message);
        res.status(500).send('Failed to exchange authorization code for tokens.');
    }
});

app.get('/logout', (req, res) => {
    const logoutUrl = `https://${AUTH0_DOMAIN}/v2/logout?client_id=${AUTH0_CLIENT_ID}&returnTo=${encodeURIComponent(LOGOUT_RETURN_URL)}`;
    res.redirect(logoutUrl);
});


app.post('/api/refresh', async (req, res) => {
    const { refresh_token } = req.body;

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

        const encryptedAccessToken = encryptToken(response.data.access_token);
        res.json({ ...response.data, access_token: encryptedAccessToken });
    } catch (err) {
        res.status(401).json({ error: 'Refresh failed' });
    }
});

app.get('/api/profile', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token' });

    const encryptedToken = authHeader.replace('Bearer ', '').trim();
    let originalToken;

    try {
        originalToken = decryptToken(encryptedToken);
    } catch (e) {
        return res.status(401).json({ error: 'Invalid encrypted token format' });
    }

    jwt.verify(originalToken, auth0PublicKey, {
        audience: AUTH0_AUDIENCE,
        issuer: `https://${AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token signature' });

        const timeLeft = (decoded.exp * 1000) - Date.now();
        if (timeLeft < 60000) return res.status(401).json({ error: 'Token expiring soon', needRefresh: true });

        res.json({ message: 'Token valid', user: decoded });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));