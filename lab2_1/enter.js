require('dotenv').config();
const axios = require('axios');

const authConfig = {
    domain: process.env.AUTH0_DOMAIN,
    clientId: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    username: process.env.AUTH0_USERNAME,
    password: process.env.AUTH0_PASSWORD,
    namespace: process.env.AUTH0_NAMESPACE,
    audience: process.env.AUTH0_AUDIENCE
};

function decodeToken(token) {
    if (!token) return {};
    try {
        const base64Payload = token.split('.')[1];
        const payload = Buffer.from(base64Payload, 'base64').toString();
        return JSON.parse(payload);
    } catch (e) {
        return { error: 'Failed to decode' };
    }
}

async function performLogin(attempt) {
    try {
        const response = await axios.post(`https://${authConfig.domain}/oauth/token`, {
            grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
            realm: 'Username-Password-Authentication',
            username: authConfig.username,
            password: authConfig.password,
            audience: authConfig.audience,
            scope: 'openid profile email',
            client_id: authConfig.clientId,
            client_secret: authConfig.clientSecret
        });

        const idToken = response.data.id_token;
        const decoded = decodeToken(idToken);

        const roles = decoded[`${authConfig.namespace}/roles`] || [];

        console.log(`[Attempt #${attempt.toString().padStart(2, '0')}]`);
        console.log(`Status: SUCCESS`);
        console.log(`Time: ${new Date().toLocaleTimeString()}`);
        console.log(`Roles in JWT: [ ${roles.join(' | ')} ]`);
        console.log('------------------------------------------------------------');

    } catch (error) {
        const errorMsg = error.response?.data?.error_description || error.message;
        console.error(`[Attempt #${attempt}] FAILED: ${errorMsg}`);
    }
}

async function startSimulation() {
    console.log('============================================================');
    console.log(`Multi-role simulation`);
    console.log(`Target: ${authConfig.domain}`);
    console.log(`User: ${authConfig.username}`);
    console.log('============================================================\n');

    for (let i = 1; i <= 10; i++) {
        await performLogin(i);
        await new Promise(r => setTimeout(r, 10000));
    }

    console.log('Simulation finished successfully.');
}

startSimulation();