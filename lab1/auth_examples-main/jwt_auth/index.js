const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';


const SECRET_KEY = process.env.JWT_SECRET;

if (!SECRET_KEY) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in .env file");
    process.exit(1);
}

// Middleware
app.use((req, res, next) => {
    let token = req.get(SESSION_KEY);


    if (token && token.startsWith('Bearer ')) {
        token = token.slice(7, token.length);
    }

    if (token) {
        try {
            const decoded = jwt.verify(token, SECRET_KEY);
            req.session = decoded;
            req.sessionId = token;
        } catch (err) {
            req.session = {};
            req.sessionId = null;
        }
    } else {
        req.session = {};
        req.sessionId = null;
    }
    next();
});

app.get('/', (req, res) => {
    if (req.session && req.session.username) {
        return res.json({
            username: req.session.username,
            logout: `http://localhost:${port}/logout`
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    res.redirect('/');
});

const users = [
    { login: 'Login', password: 'Password', username: 'Username' },
    { login: 'Login1', password: 'Password1', username: 'Username1' }
];

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((u) => u.login === login && u.password === password);

    if (user) {
        const token = jwt.sign(
            { username: user.username, login: user.login },
            SECRET_KEY,
            { expiresIn: '24h' }
        );

        return res.json({ token: token });
    }

    res.status(401).send('Unauthorized');
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});