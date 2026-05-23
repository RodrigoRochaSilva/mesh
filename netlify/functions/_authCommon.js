'use strict';

const ALLOWED_USER_TYPES = new Set(['team', 'guest', 'full']);
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const rateLimitStore = new Map();
const MAX_FAILED_ATTEMPTS = 3;
const LOCKOUT_MS = 120 * 1000;
const ENTRY_TTL_MS = 30 * 60 * 1000;
const loginThrottleStore = new Map();

function getEnvConfig() {
  const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
  const anonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

  return { supabaseUrl, anonKey, serviceRoleKey, allowedOrigins };
}

function getRequestIp(headers) {
  return (
    headers['x-nf-client-connection-ip'] ||
    headers['x-forwarded-for'] ||
    headers['client-ip'] ||
    'unknown'
  )
    .split(',')[0]
    .trim();
}

function cleanupRateLimitStore(now) {
  for (const [key, value] of rateLimitStore.entries()) {
    if (now - value.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
      rateLimitStore.delete(key);
    }
  }
}

function checkRateLimit(ip, email) {
  const now = Date.now();
  cleanupRateLimitStore(now);
  const bucketKey = `${ip}:${(email || '').toLowerCase().trim()}`;
  const existing = rateLimitStore.get(bucketKey);

  if (!existing) {
    rateLimitStore.set(bucketKey, { firstAttemptAt: now, attempts: 1 });
    return { allowed: true };
  }

  if (now - existing.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(bucketKey, { firstAttemptAt: now, attempts: 1 });
    return { allowed: true };
  }

  existing.attempts += 1;
  rateLimitStore.set(bucketKey, existing);
  const allowed = existing.attempts <= RATE_LIMIT_MAX_ATTEMPTS;
  return {
    allowed,
    retryAfterSeconds: allowed
      ? 0
      : Math.ceil((RATE_LIMIT_WINDOW_MS - (now - existing.firstAttemptAt)) / 1000),
  };
}

function buildThrottleBucketKey(ip, email) {
  return `${ip}:${(email || '').toLowerCase().trim()}`;
}

function cleanupThrottleStore(now) {
  for (const [key, value] of loginThrottleStore.entries()) {
    if (!value || (now - Number(value.updatedAt || 0)) > ENTRY_TTL_MS) {
      loginThrottleStore.delete(key);
    }
  }
}

function getLoginThrottleState(ip, email) {
  const now = Date.now();
  cleanupThrottleStore(now);
  const bucketKey = buildThrottleBucketKey(ip, email);
  const existing = loginThrottleStore.get(bucketKey);
  if (!existing) return { allowed: true, retryAfterSeconds: 0 };

  if (Number(existing.blockedUntil || 0) > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((existing.blockedUntil - now) / 1000),
    };
  }

  return { allowed: true, retryAfterSeconds: 0 };
}

function registerLoginFailure(ip, email) {
  const now = Date.now();
  cleanupThrottleStore(now);
  const bucketKey = buildThrottleBucketKey(ip, email);
  const existing = loginThrottleStore.get(bucketKey) || {
    failedAttempts: 0,
    blockedUntil: 0,
    updatedAt: now,
  };

  if (Number(existing.blockedUntil || 0) > now) {
    existing.updatedAt = now;
    loginThrottleStore.set(bucketKey, existing);
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((existing.blockedUntil - now) / 1000),
      failedAttempts: existing.failedAttempts,
    };
  }

  const nextFailedAttempts = Number(existing.failedAttempts || 0) + 1;
  const shouldBlock = nextFailedAttempts >= MAX_FAILED_ATTEMPTS;
  const blockedUntil = shouldBlock ? now + LOCKOUT_MS : 0;
  const state = {
    failedAttempts: nextFailedAttempts,
    blockedUntil,
    updatedAt: now,
  };
  loginThrottleStore.set(bucketKey, state);

  return {
    allowed: !shouldBlock,
    retryAfterSeconds: shouldBlock ? Math.ceil(LOCKOUT_MS / 1000) : 0,
    failedAttempts: state.failedAttempts,
  };
}

function clearLoginFailures(ip, email) {
  const bucketKey = buildThrottleBucketKey(ip, email);
  loginThrottleStore.delete(bucketKey);
}

function sanitizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function buildCorsHeaders(origin, allowedOrigins) {
  const fallbackOrigins = ['http://localhost:8080', 'http://127.0.0.1:8080'];
  const effectiveOrigins = allowedOrigins.length > 0 ? allowedOrigins : fallbackOrigins;
  const isAllowed = !!origin && effectiveOrigins.includes(origin);
  const resolvedOrigin = isAllowed ? origin : 'null';

  return {
    'Access-Control-Allow-Origin': resolvedOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    Vary: 'Origin',
    'Cache-Control': 'no-store',
  };
}

function isOriginAllowed(origin, allowedOrigins) {
  const fallbackOrigins = ['http://localhost:8080', 'http://127.0.0.1:8080'];
  const effectiveOrigins = allowedOrigins.length > 0 ? allowedOrigins : fallbackOrigins;
  return !!origin && effectiveOrigins.includes(origin);
}

function jsonResponse(statusCode, payload, corsHeaders, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(payload),
  };
}

function parseBody(body) {
  if (!body) return {};
  try {
    return JSON.parse(body);
  } catch (_) {
    return null;
  }
}

function isEligibleProfile(profile) {
  if (!profile) return false;
  return ALLOWED_USER_TYPES.has(profile.user_type);
}

async function signInWithPassword({ supabaseUrl, anonKey, email, password }) {
  const resp = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  if (!resp.ok) {
    return { error: true, status: resp.status, data: null };
  }

  return { error: false, status: resp.status, data: await resp.json() };
}

async function refreshSession({ supabaseUrl, anonKey, refreshToken }) {
  const resp = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=refresh_token`, {
    method: 'POST',
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!resp.ok) return { error: true, status: resp.status, data: null };
  return { error: false, status: resp.status, data: await resp.json() };
}

async function getProfileByUserId({ supabaseUrl, serviceRoleKey, userId }) {
  const qs = new URLSearchParams({
    select: 'id,email,user_type,plan_type,subscription_status,plan_valid_until',
    id: `eq.${userId}`,
    limit: '1',
  });

  const resp = await fetch(`${supabaseUrl}/rest/v1/profiles?${qs.toString()}`, {
    method: 'GET',
    headers: {
      apikey: serviceRoleKey,
      Authorization: `Bearer ${serviceRoleKey}`,
      Accept: 'application/json',
    },
  });

  if (!resp.ok) return { error: true, status: resp.status, data: null };
  const arr = await resp.json();
  return { error: false, status: resp.status, data: Array.isArray(arr) ? arr[0] || null : null };
}

async function getUserFromAccessToken({ supabaseUrl, anonKey, accessToken }) {
  const resp = await fetch(`${supabaseUrl}/auth/v1/user`, {
    method: 'GET',
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!resp.ok) return { error: true, status: resp.status, data: null };
  return { error: false, status: resp.status, data: await resp.json() };
}

module.exports = {
  getEnvConfig,
  getRequestIp,
  checkRateLimit,
  getLoginThrottleState,
  registerLoginFailure,
  clearLoginFailures,
  cleanupThrottleStore,
  sanitizeEmail,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
  parseBody,
  isEligibleProfile,
  signInWithPassword,
  refreshSession,
  getProfileByUserId,
  getUserFromAccessToken,
};
