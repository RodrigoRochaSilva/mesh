// Simple HTTP server for local development
// Run: node server.js
// Open: http://localhost:8080

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const {
    getEnvConfig,
    getRequestIp,
    checkRateLimit,
    sanitizeEmail,
    buildCorsHeaders,
    isOriginAllowed,
    isEligibleProfile,
    signInWithPassword,
    refreshSession,
    getProfileByUserId,
    buildGoogleAuthorizeUrl,
    isValidPkceChallenge,
    isValidPkceVerifier,
    isValidAuthCode,
    isSafeRedirectPath,
    exchangeCodeForSession
} = require('./netlify/functions/_authCommon');

const PORT = 8080;

function loadEnvFile(filename) {
    const fullPath = path.join(__dirname, filename);
    if (!fs.existsSync(fullPath)) return;
    const lines = fs.readFileSync(fullPath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq <= 0) continue;
        const key = trimmed.slice(0, eq).trim();
        const value = trimmed.slice(eq + 1).trim();
        if (!process.env[key]) {
            process.env[key] = value;
        }
    }
}

loadEnvFile('.env');
loadEnvFile('.env.local');

const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.manifest': 'application/manifest+json'
};

function sendJson(res, statusCode, payload, headers) {
    res.writeHead(statusCode, {
        ...headers,
        'Content-Type': 'application/json'
    });
    res.end(JSON.stringify(payload));
}

function readBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk.toString();
        });
        req.on('end', () => resolve(body));
    });
}

async function handleAuthLogin(req, res, corsHeaders) {
    const { supabaseUrl, anonKey, serviceRoleKey } = getEnvConfig();
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
        sendJson(res, 500, { error: 'server_misconfigured' }, corsHeaders);
        return;
    }

    const rawBody = await readBody(req);
    let body = null;
    try {
        body = JSON.parse(rawBody || '{}');
    } catch (_) {
        sendJson(res, 400, { error: 'invalid_json' }, corsHeaders);
        return;
    }

    const email = sanitizeEmail(body.email);
    const password = String(body.password || '');
    if (!email || !password) {
        sendJson(res, 400, { error: 'missing_credentials' }, corsHeaders);
        return;
    }

    const ip = getRequestIp(req.headers);
    const rate = checkRateLimit(ip, email);
    if (!rate.allowed) {
        sendJson(res, 429, { error: 'too_many_attempts' }, {
            ...corsHeaders,
            'Retry-After': String(rate.retryAfterSeconds || 60)
        });
        return;
    }

    try {
        const loginResp = await signInWithPassword({ supabaseUrl, anonKey, email, password });
        if (loginResp.error || !loginResp.data || !loginResp.data.user) {
            sendJson(res, 401, { error: 'invalid_credentials' }, corsHeaders);
            return;
        }

        const profileResp = await getProfileByUserId({
            supabaseUrl,
            serviceRoleKey,
            userId: loginResp.data.user.id
        });
        if (profileResp.error || !profileResp.data) {
            sendJson(res, 403, { error: 'access_denied' }, corsHeaders);
            return;
        }

        if (!isEligibleProfile(profileResp.data)) {
            sendJson(res, 403, { error: 'user_type_not_allowed' }, corsHeaders);
            return;
        }

        sendJson(res, 200, {
            session: {
                access_token: loginResp.data.access_token,
                refresh_token: loginResp.data.refresh_token,
                expires_in: loginResp.data.expires_in,
                expires_at: loginResp.data.expires_at,
                token_type: loginResp.data.token_type
            },
            user: {
                id: loginResp.data.user.id,
                email: loginResp.data.user.email
            },
            profile: profileResp.data
        }, corsHeaders);
    } catch (_) {
        sendJson(res, 500, { error: 'internal_error' }, corsHeaders);
    }
}

async function handleAuthValidate(req, res, corsHeaders) {
    const { supabaseUrl, anonKey, serviceRoleKey } = getEnvConfig();
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
        sendJson(res, 500, { error: 'server_misconfigured' }, corsHeaders);
        return;
    }

    const rawBody = await readBody(req);
    let body = null;
    try {
        body = JSON.parse(rawBody || '{}');
    } catch (_) {
        sendJson(res, 400, { error: 'invalid_json' }, corsHeaders);
        return;
    }

    const refreshToken = String(body.refresh_token || '');
    if (!refreshToken) {
        sendJson(res, 401, { error: 'invalid_session' }, corsHeaders);
        return;
    }

    try {
        const refreshResp = await refreshSession({ supabaseUrl, anonKey, refreshToken });
        if (refreshResp.error || !refreshResp.data || !refreshResp.data.user) {
            sendJson(res, 401, { error: 'invalid_session' }, corsHeaders);
            return;
        }

        const profileResp = await getProfileByUserId({
            supabaseUrl,
            serviceRoleKey,
            userId: refreshResp.data.user.id
        });
        if (profileResp.error || !profileResp.data) {
            sendJson(res, 403, { error: 'access_denied' }, corsHeaders);
            return;
        }

        if (!isEligibleProfile(profileResp.data)) {
            sendJson(res, 403, { error: 'user_type_not_allowed' }, corsHeaders);
            return;
        }

        sendJson(res, 200, {
            session: {
                access_token: refreshResp.data.access_token,
                refresh_token: refreshResp.data.refresh_token,
                expires_in: refreshResp.data.expires_in,
                expires_at: refreshResp.data.expires_at,
                token_type: refreshResp.data.token_type
            },
            user: {
                id: refreshResp.data.user.id,
                email: refreshResp.data.user.email
            },
            profile: profileResp.data
        }, corsHeaders);
    } catch (_) {
        sendJson(res, 500, { error: 'internal_error' }, corsHeaders);
    }
}

async function handleOAuthGoogleStart(req, res, corsHeaders, origin) {
    const { supabaseUrl, anonKey, oauthRedirectPath } = getEnvConfig();
    if (!supabaseUrl || !anonKey) {
        sendJson(res, 500, { error: 'server_misconfigured' }, corsHeaders);
        return;
    }

    const rawBody = await readBody(req);
    let body = {};
    try {
        body = JSON.parse(rawBody || '{}');
    } catch (_) {
        sendJson(res, 400, { error: 'invalid_json' }, corsHeaders);
        return;
    }

    const codeChallenge = String((body && body.code_challenge) || '');
    if (!isValidPkceChallenge(codeChallenge)) {
        sendJson(res, 400, { error: 'invalid_code_challenge' }, corsHeaders);
        return;
    }

    const requestedRedirect = (body && body.redirect_path) ? String(body.redirect_path) : '';
    const defaultRedirect = oauthRedirectPath || '/oauth-callback.html';
    const redirectPath = requestedRedirect && isSafeRedirectPath(requestedRedirect)
        ? requestedRedirect
        : defaultRedirect;

    const requestHost = String(req.headers.host || 'localhost:8080');
    const inferredOrigin = `http://${requestHost}`;
    const requestOrigin = origin || inferredOrigin;
    const redirectTo = `${requestOrigin}${redirectPath}`;

    const authorizeUrl = buildGoogleAuthorizeUrl({
        supabaseUrl,
        redirectTo,
        codeChallenge
    });

    sendJson(res, 200, {
        provider: 'google',
        authorize_url: authorizeUrl,
        redirect_to: redirectTo
    }, corsHeaders);
}

async function handleOAuthGoogleComplete(req, res, corsHeaders) {
    const { supabaseUrl, anonKey, serviceRoleKey } = getEnvConfig();
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
        sendJson(res, 500, { error: 'server_misconfigured' }, corsHeaders);
        return;
    }

    const rawBody = await readBody(req);
    let body = null;
    try {
        body = JSON.parse(rawBody || '{}');
    } catch (_) {
        sendJson(res, 400, { error: 'invalid_json' }, corsHeaders);
        return;
    }

    const authCode = String(body.code || '');
    const codeVerifier = String(body.code_verifier || '');

    if (!isValidAuthCode(authCode) || !isValidPkceVerifier(codeVerifier)) {
        sendJson(res, 400, { error: 'invalid_pkce_payload' }, corsHeaders);
        return;
    }

    const ip = getRequestIp(req.headers);
    const rate = checkRateLimit(ip, 'oauth-google');
    if (!rate.allowed) {
        sendJson(res, 429, { error: 'too_many_attempts' }, {
            ...corsHeaders,
            'Retry-After': String(rate.retryAfterSeconds || 60)
        });
        return;
    }

    try {
        const tokenResp = await exchangeCodeForSession({
            supabaseUrl,
            anonKey,
            authCode,
            codeVerifier
        });
        if (tokenResp.error || !tokenResp.data || !tokenResp.data.access_token || !tokenResp.data.user) {
            sendJson(res, 401, { error: 'invalid_session' }, corsHeaders);
            return;
        }

        const tokenData = tokenResp.data;

        const profileResp = await getProfileByUserId({
            supabaseUrl,
            serviceRoleKey,
            userId: tokenData.user.id
        });
        if (profileResp.error || !profileResp.data) {
            sendJson(res, 403, { error: 'access_denied' }, corsHeaders);
            return;
        }

        if (!isEligibleProfile(profileResp.data)) {
            sendJson(res, 403, { error: 'user_type_not_allowed' }, corsHeaders);
            return;
        }

        const expiresIn = Number(tokenData.expires_in || 3600);
        const expiresAt = Number(tokenData.expires_at || (Math.floor(Date.now() / 1000) + expiresIn));

        sendJson(res, 200, {
            session: {
                access_token: tokenData.access_token,
                refresh_token: tokenData.refresh_token,
                expires_in: expiresIn,
                expires_at: expiresAt,
                token_type: tokenData.token_type || 'bearer'
            },
            user: {
                id: tokenData.user.id,
                email: tokenData.user.email || ''
            },
            profile: profileResp.data
        }, corsHeaders);
    } catch (_) {
        sendJson(res, 500, { error: 'internal_error' }, corsHeaders);
    }
}

function serveStatic(req, res) {
    let filePath = '.' + req.url.split('?')[0];

    if (filePath === './') {
        filePath = './index.html';
    }

    const extname = String(path.extname(filePath)).toLowerCase();
    const contentType = mimeTypes[extname] || 'application/octet-stream';

    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end('<h1>404 - File not found</h1>', 'utf-8');
            } else {
                res.writeHead(500);
                res.end(`Server error: ${error.code}`, 'utf-8');
            }
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
}

const server = http.createServer(async (req, res) => {
    const { allowedOrigins } = getEnvConfig();
    const origin = req.headers.origin || '';
    const corsHeaders = buildCorsHeaders(origin, allowedOrigins);

    if (req.method === 'OPTIONS' && req.url.startsWith('/api/')) {
        sendJson(res, 200, { ok: true }, corsHeaders);
        return;
    }

    if (req.url.startsWith('/api/') && !isOriginAllowed(origin, allowedOrigins)) {
        sendJson(res, 403, { error: 'origin_not_allowed' }, corsHeaders);
        return;
    }

    if (req.url === '/api/auth/login' || req.url === '/api-proxy/auth_mexe') {
        if (req.method !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' }, corsHeaders);
            return;
        }
        await handleAuthLogin(req, res, corsHeaders);
        return;
    }

    if (req.url === '/api/auth/validate') {
        if (req.method !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' }, corsHeaders);
            return;
        }
        await handleAuthValidate(req, res, corsHeaders);
        return;
    }

    if (req.url === '/api/auth/logout') {
        if (req.method !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' }, corsHeaders);
            return;
        }
        sendJson(res, 200, { ok: true }, corsHeaders);
        return;
    }

    if (req.url === '/api/auth/oauth/google/start') {
        if (req.method !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' }, corsHeaders);
            return;
        }
        await handleOAuthGoogleStart(req, res, corsHeaders, origin);
        return;
    }

    if (req.url === '/api/auth/oauth/google/complete') {
        if (req.method !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' }, corsHeaders);
            return;
        }
        await handleOAuthGoogleComplete(req, res, corsHeaders);
        return;
    }

    serveStatic(req, res);
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
