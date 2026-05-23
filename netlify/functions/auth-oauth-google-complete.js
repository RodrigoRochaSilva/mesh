'use strict';

const {
  getEnvConfig,
  getRequestIp,
  checkRateLimit,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
  parseBody,
  isEligibleProfile,
  getProfileByUserId,
  exchangeCodeForSession,
  isValidPkceVerifier,
  isValidAuthCode,
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

  if (!isOriginAllowed(origin, allowedOrigins)) {
    return jsonResponse(403, { error: 'origin_not_allowed' }, corsHeaders);
  }

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return jsonResponse(500, { error: 'server_misconfigured' }, corsHeaders);
  }

  const body = parseBody(event.body);
  if (!body) return jsonResponse(400, { error: 'invalid_json' }, corsHeaders);

  const authCode = String(body.code || '');
  const codeVerifier = String(body.code_verifier || '');

  if (!isValidAuthCode(authCode) || !isValidPkceVerifier(codeVerifier)) {
    return jsonResponse(400, { error: 'invalid_pkce_payload' }, corsHeaders);
  }

  const ip = getRequestIp(event.headers);
  const rate = checkRateLimit(ip, 'oauth-google');
  if (!rate.allowed) {
    return jsonResponse(
      429,
      { error: 'too_many_attempts' },
      corsHeaders,
      { 'Retry-After': String(rate.retryAfterSeconds || 60) }
    );
  }

  try {
    const tokenResp = await exchangeCodeForSession({
      supabaseUrl,
      anonKey,
      authCode,
      codeVerifier,
    });
    if (tokenResp.error || !tokenResp.data || !tokenResp.data.access_token || !tokenResp.data.user) {
      return jsonResponse(401, { error: 'invalid_session' }, corsHeaders);
    }

    const tokenData = tokenResp.data;

    const profileResp = await getProfileByUserId({
      supabaseUrl,
      serviceRoleKey,
      userId: tokenData.user.id,
    });
    if (profileResp.error || !profileResp.data) {
      return jsonResponse(403, { error: 'access_denied' }, corsHeaders);
    }

    if (!isEligibleProfile(profileResp.data)) {
      return jsonResponse(403, { error: 'user_type_not_allowed' }, corsHeaders);
    }

    const expiresIn = Number(tokenData.expires_in || 3600);
    const expiresAt = Number(tokenData.expires_at || (Math.floor(Date.now() / 1000) + expiresIn));

    return jsonResponse(
      200,
      {
        session: {
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token,
          expires_in: expiresIn,
          expires_at: expiresAt,
          token_type: tokenData.token_type || 'bearer',
        },
        user: {
          id: tokenData.user.id,
          email: tokenData.user.email || '',
        },
        profile: profileResp.data,
      },
      corsHeaders
    );
  } catch (_) {
    return jsonResponse(500, { error: 'internal_error' }, corsHeaders);
  }
};
