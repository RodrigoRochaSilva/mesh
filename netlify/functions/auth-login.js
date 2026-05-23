'use strict';

const {
  getEnvConfig,
  getRequestIp,
  getLoginThrottleState,
  registerLoginFailure,
  clearLoginFailures,
  sanitizeEmail,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
  parseBody,
  isEligibleProfile,
  signInWithPassword,
  getProfileByUserId,
} = require('./_authCommon');

exports.handler = async (event) => {
  const { supabaseUrl, anonKey, serviceRoleKey, allowedOrigins } = getEnvConfig();
  const origin = event.headers.origin || '';
  const corsHeaders = buildCorsHeaders(origin, allowedOrigins);

  if (event.httpMethod === 'OPTIONS') {
    return jsonResponse(200, { ok: true }, corsHeaders);
  }

  if (event.httpMethod !== 'POST') {
    return jsonResponse(405, { error: 'method_not_allowed' }, corsHeaders);
  }

  // TEMP DIAGNOSTIC — remove after CORS issue is resolved.
  console.log('[auth-login] origin header =', JSON.stringify(origin));
  console.log('[auth-login] CORS_ALLOWED_ORIGINS raw =', JSON.stringify(process.env.CORS_ALLOWED_ORIGINS || ''));
  console.log('[auth-login] allowedOrigins parsed =', JSON.stringify(allowedOrigins));
  console.log('[auth-login] isOriginAllowed =', isOriginAllowed(origin, allowedOrigins));

  if (!isOriginAllowed(origin, allowedOrigins)) {
    return jsonResponse(403, { error: 'origin_not_allowed' }, corsHeaders);
  }

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return jsonResponse(500, { error: 'server_misconfigured' }, corsHeaders);
  }

  const body = parseBody(event.body);
  if (!body) return jsonResponse(400, { error: 'invalid_json' }, corsHeaders);

  const email = sanitizeEmail(body.email);
  const password = String(body.password || '');

  if (!email || !password) {
    return jsonResponse(400, { error: 'missing_credentials' }, corsHeaders);
  }

  const ip = getRequestIp(event.headers);
  const throttle = getLoginThrottleState(ip, email);
  if (!throttle.allowed) {
    return jsonResponse(
      429,
      { error: 'too_many_attempts' },
      corsHeaders,
      { 'Retry-After': String(throttle.retryAfterSeconds || 120) }
    );
  }

  try {
    const loginResp = await signInWithPassword({ supabaseUrl, anonKey, email, password });
    if (loginResp.error || !loginResp.data || !loginResp.data.user) {
      const failureState = registerLoginFailure(ip, email);
      if (!failureState.allowed) {
        return jsonResponse(
          429,
          { error: 'too_many_attempts' },
          corsHeaders,
          { 'Retry-After': String(failureState.retryAfterSeconds || 120) }
        );
      }
      return jsonResponse(401, { error: 'invalid_credentials' }, corsHeaders);
    }

    const profileResp = await getProfileByUserId({
      supabaseUrl,
      serviceRoleKey,
      userId: loginResp.data.user.id,
    });
    if (profileResp.error || !profileResp.data) {
      return jsonResponse(403, { error: 'access_denied' }, corsHeaders);
    }

    if (!isEligibleProfile(profileResp.data)) {
      return jsonResponse(403, { error: 'user_type_not_allowed' }, corsHeaders);
    }

    clearLoginFailures(ip, email);

    return jsonResponse(
      200,
      {
        session: {
          access_token: loginResp.data.access_token,
          refresh_token: loginResp.data.refresh_token,
          expires_in: loginResp.data.expires_in,
          expires_at: loginResp.data.expires_at,
          token_type: loginResp.data.token_type,
        },
        user: {
          id: loginResp.data.user.id,
          email: loginResp.data.user.email,
        },
        profile: profileResp.data,
      },
      corsHeaders
    );
  } catch (_) {
    return jsonResponse(500, { error: 'internal_error' }, corsHeaders);
  }
};
