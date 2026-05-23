// mexe authentication module (Supabase)

const env = window['MexeEnv'] || {};
const AUTH_BASE_URL = env['authBaseUrl'] || '/api/auth';

const SESSION_KEY = 'mexe_session';
const PKCE_VERIFIER_KEY = 'mexe_pkce_verifier';
const EXPIRATION_CHECK_INTERVAL = 300000; // 5 min
const REFRESH_SKEW_MS = 60000;
const ONLINE_VALIDATION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const PLAN_GRACE_MS = 24 * 60 * 60 * 1000; // 24h

let expirationCheckInterval = null;

const storage = localforage.createInstance({
    name: 'mexe',
    storeName: 'auth'
});

function createAuthError(message, status, code) {
    const error = new Error(message);
    error.status = status || 500;
    error.code = code || 'auth_error';
    return error;
}

function mapAuthErrorMessage(status, code) {
    if (status === 401) return 'Incorrect email or password.';
    if (status === 403) {
        if (code === 'plan_not_allowed' || code === 'user_type_not_allowed') {
            return 'Your account type is not allowed to access this app. Please contact your administrator.';
        }
        if (code === 'origin_not_allowed') {
            return 'This app origin is not allowed by the authentication server configuration.';
        }
        return 'Access denied. Please contact support if you believe this is a mistake.';
    }
    if (status === 429) return null;
    if (status >= 500) return 'Authentication service is unavailable right now. Please try again in a moment.';
    return 'Could not complete authentication. Please try again.';
}

function getRetryAfterSeconds(response, data) {
    const headerValue = response && response.headers ? response.headers.get('Retry-After') : null;
    const parsedHeader = headerValue ? Number(headerValue) : NaN;
    if (Number.isFinite(parsedHeader) && parsedHeader > 0) return Math.ceil(parsedHeader);
    const parsedPayload = data && Number.isFinite(Number(data.retry_after_seconds))
        ? Number(data.retry_after_seconds)
        : NaN;
    if (Number.isFinite(parsedPayload) && parsedPayload > 0) return Math.ceil(parsedPayload);
    return 120;
}

function toTimestamp(value) {
    if (!value) return null;
    const n = typeof value === 'number' ? value : Date.parse(String(value));
    if (!Number.isFinite(n)) return null;
    return n;
}

function computeOfflineAccessUntil(lastOnlineValidationAt, planValidUntil) {
    const capByValidation = lastOnlineValidationAt + ONLINE_VALIDATION_MAX_AGE_MS;
    const planTs = toTimestamp(planValidUntil);
    if (!planTs) return capByValidation;
    return Math.min(capByValidation, planTs + PLAN_GRACE_MS);
}

function isOfflineAccessAllowed(session, nowTs) {
    if (!session) return false;
    const lastValidation = Number(session.last_online_validation_at || 0);
    if (!lastValidation) return false;

    const byValidation = lastValidation + ONLINE_VALIDATION_MAX_AGE_MS;
    const planTs = toTimestamp(session.plan_valid_until);
    if (!planTs) return false;
    const byPlan = planTs + PLAN_GRACE_MS;

    return nowTs <= byValidation && nowTs <= byPlan;
}

async function requestAuth(path, payload) {
    const response = await fetch(`${AUTH_BASE_URL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {}),
        cache: 'no-cache'
    });

    let data = null;
    try {
        data = await response.json();
    } catch (_) {
        data = null;
    }

    if (!response.ok) {
        const code = data && data.error ? data.error : 'request_failed';
        if (response.status === 401) throw createAuthError(mapAuthErrorMessage(401, code), 401, code);
        if (response.status === 403) throw createAuthError(mapAuthErrorMessage(403, code), 403, code);
        if (response.status === 429) {
            const retryAfterSeconds = getRetryAfterSeconds(response, data);
            const retryLabel = retryAfterSeconds === 120
                ? '2 minutes'
                : `${retryAfterSeconds} seconds`;
            const error = createAuthError(`Too many attempts. Please wait ${retryLabel}.`, 429, code);
            error.retryAfterSeconds = retryAfterSeconds;
            throw error;
        }
        throw createAuthError(mapAuthErrorMessage(response.status, code), response.status, code);
    }

    return data;
}

function normalizeSession(serverData, emailInput, previousSession) {
    const now = Date.now();
    const expiresAtMs = serverData.session && serverData.session.expires_at
        ? Number(serverData.session.expires_at) * 1000
        : now + ((serverData.session && serverData.session.expires_in ? Number(serverData.session.expires_in) : 3600) * 1000);

    const lastOnlineValidationAt = now;
    const offlineAccessUntil = computeOfflineAccessUntil(lastOnlineValidationAt, serverData.profile.plan_valid_until);

    return {
        user_id: serverData.user.id,
        email: serverData.user.email || emailInput || '',
        user_type: serverData.profile.user_type || 'unknown',
        plano: serverData.profile.plan_type || 'unknown',
        subscription_status: serverData.profile.subscription_status || 'unknown',
        plan_valid_until: serverData.profile.plan_valid_until || null,
        expires: expiresAtMs,
        loginDate: (previousSession && previousSession.loginDate) || now,
        lastValidation: now,
        last_online_validation_at: lastOnlineValidationAt,
        offline_access_until: offlineAccessUntil,
        session: {
            access_token: serverData.session.access_token,
            refresh_token: serverData.session.refresh_token,
            expires_at: serverData.session.expires_at,
            expires_in: serverData.session.expires_in,
            token_type: serverData.session.token_type
        }
    };
}

async function saveSession(data) { await storage.setItem(SESSION_KEY, data); }
async function getSession() { return await storage.getItem(SESSION_KEY); }

async function authenticate(email, password) {
    if (!email || !password) throw createAuthError('Please enter your email and password.', 400, 'missing_credentials');
    const data = await requestAuth('/login', {
        email: email.trim().toLowerCase(),
        password
    });
    if (!data || !data.session || !data.user || !data.profile) {
        throw createAuthError('Invalid authentication response.', 500, 'invalid_auth_response');
    }
    const sessionData = normalizeSession(data, email.trim().toLowerCase(), null);
    await saveSession(sessionData);
    startExpirationCheck();
    return sessionData;
}

function base64UrlEncode(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generatePkceVerifier() {
    const bytes = new Uint8Array(48);
    window.crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
}

async function computePkceChallenge(verifier) {
    const data = new TextEncoder().encode(verifier);
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(digest));
}

function storePkceVerifier(verifier) {
    try {
        window.sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
    } catch (_) {
        throw createAuthError(
            'Session storage is unavailable. Enable site data to sign in with Google.',
            500,
            'pkce_storage_unavailable'
        );
    }
}

function consumePkceVerifier() {
    try {
        const verifier = window.sessionStorage.getItem(PKCE_VERIFIER_KEY);
        window.sessionStorage.removeItem(PKCE_VERIFIER_KEY);
        return verifier || '';
    } catch (_) {
        return '';
    }
}

async function startGoogleOAuth() {
    if (!window.crypto || !window.crypto.subtle) {
        throw createAuthError('Secure cryptography is not available in this browser.', 500, 'crypto_unavailable');
    }
    const verifier = generatePkceVerifier();
    const challenge = await computePkceChallenge(verifier);
    storePkceVerifier(verifier);

    const data = await requestAuth('/oauth/google/start', {
        redirect_path: '/oauth-callback.html',
        code_challenge: challenge
    });
    if (!data || !data.authorize_url) {
        throw createAuthError('Could not start Google sign-in.', 500, 'oauth_start_failed');
    }
    window.location.assign(data.authorize_url);
}

async function completeGoogleOAuth(payload) {
    const data = await requestAuth('/oauth/google/complete', payload);
    if (!data || !data.session || !data.user || !data.profile) {
        throw createAuthError('Invalid OAuth response.', 500, 'invalid_auth_response');
    }
    const previous = await getSession();
    const sessionData = normalizeSession(data, data.user.email || '', previous);
    await saveSession(sessionData);
    startExpirationCheck();
    return sessionData;
}

function parseOAuthCodeFromLocation() {
    const hashStr = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
    const queryStr = window.location.search.startsWith('?') ? window.location.search.slice(1) : window.location.search;
    const hash = new URLSearchParams(hashStr || '');
    const query = new URLSearchParams(queryStr || '');

    return {
        code: query.get('code') || hash.get('code') || '',
        oauth_error: query.get('error') || hash.get('error') || '',
        oauth_error_description: query.get('error_description') || hash.get('error_description') || ''
    };
}

async function completeGoogleOAuthFromCurrentUrl() {
    const parsed = parseOAuthCodeFromLocation();
    if (parsed.oauth_error) {
        consumePkceVerifier();
        const msg = parsed.oauth_error_description
            ? decodeURIComponent(String(parsed.oauth_error_description).replace(/\+/g, '%20'))
            : parsed.oauth_error;
        throw createAuthError(`Google OAuth error: ${msg}`, 401, 'oauth_error');
    }
    if (!parsed.code) {
        consumePkceVerifier();
        throw createAuthError('OAuth callback did not include an authorization code.', 401, 'oauth_missing_code');
    }

    const verifier = consumePkceVerifier();
    if (!verifier) {
        throw createAuthError(
            'Could not complete Google sign-in: PKCE verifier missing. Please try again from the sign-in screen.',
            401,
            'oauth_verifier_missing'
        );
    }

    return await completeGoogleOAuth({ code: parsed.code, code_verifier: verifier });
}

async function validateSessionOnServer() {
    const existing = await getSession();
    if (!existing || !existing.session || !existing.session.refresh_token) return false;

    const data = await requestAuth('/validate', {
        refresh_token: existing.session.refresh_token
    });
    if (!data || !data.session || !data.user || !data.profile) return false;

    const updated = normalizeSession(data, existing.email, existing);
    await saveSession(updated);
    return true;
}

async function isSessionValid(options) {
    const forceOnlineValidation = !!(options && options.forceOnlineValidation);
    const session = await getSession();
    if (!session || !session.session || !session.session.refresh_token) return false;

    const now = Date.now();
    const shouldRefreshToken = !session.expires || now >= (session.expires - REFRESH_SKEW_MS);
    const shouldForceOnlineValidation = !session.last_online_validation_at ||
        (now - Number(session.last_online_validation_at)) >= ONLINE_VALIDATION_MAX_AGE_MS;

    if (!navigator.onLine) {
        return isOfflineAccessAllowed(session, now);
    }

    if (forceOnlineValidation || shouldRefreshToken || shouldForceOnlineValidation) {
        try {
            return await validateSessionOnServer();
        } catch (_) {
            return isOfflineAccessAllowed(session, now);
        }
    }

    return true;
}

async function checkAuthentication(forceOnlineValidation) {
    try {
        return await isSessionValid({ forceOnlineValidation: !!forceOnlineValidation });
    } catch (_) {
        return false;
    }
}

async function logout() {
    try {
        await requestAuth('/logout', {});
    } catch (_) {
        // ignore remote failures
    }
    await storage.removeItem(SESSION_KEY);
    stopExpirationCheck();
}

function checkPlanExpiration() {
    getSession().then(async (session) => {
        if (!session) return;
        const now = Date.now();
        const mustCheck = (!session.expires || now >= (session.expires - REFRESH_SKEW_MS)) ||
            (!session.last_online_validation_at || (now - Number(session.last_online_validation_at)) >= ONLINE_VALIDATION_MAX_AGE_MS);

        if (mustCheck) {
            const ok = await checkAuthentication();
            if (!ok) {
                await logout();
                window.dispatchEvent(new CustomEvent('sessionExpired'));
            }
        }
    }).catch(() => {});
}

async function getSessionAccessState() {
    const session = await getSession();
    const now = Date.now();
    if (!session) return { hasSession: false, offlineAllowed: false, offlineAccessUntil: null };
    return {
        hasSession: true,
        offlineAllowed: isOfflineAccessAllowed(session, now),
        offlineAccessUntil: session.offline_access_until || null,
        lastOnlineValidationAt: session.last_online_validation_at || null,
        planValidUntil: session.plan_valid_until || null
    };
}

function startExpirationCheck() {
    stopExpirationCheck();
    expirationCheckInterval = setInterval(checkPlanExpiration, EXPIRATION_CHECK_INTERVAL);
}

function stopExpirationCheck() {
    if (expirationCheckInterval) {
        clearInterval(expirationCheckInterval);
        expirationCheckInterval = null;
    }
}

window.Auth = {
    authenticate,
    startGoogleOAuth,
    completeGoogleOAuthFromCurrentUrl,
    completeGoogleOAuth,
    getSession,
    getSessionAccessState,
    isSessionValid,
    checkAuthentication,
    logout,
    checkPlanExpiration,
    startExpirationCheck,
    stopExpirationCheck
};
