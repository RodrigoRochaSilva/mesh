'use strict';

const {
  getEnvConfig,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
  parseBody,
  checkMeshAccess,
  accessErrorCode,
  refreshSession,
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

  if (!isOriginAllowed(origin, allowedOrigins)) {
    return jsonResponse(403, { error: 'origin_not_allowed' }, corsHeaders);
  }

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return jsonResponse(500, { error: 'server_misconfigured' }, corsHeaders);
  }

  const body = parseBody(event.body);
  if (!body) return jsonResponse(400, { error: 'invalid_json' }, corsHeaders);

  const refreshToken = String(body.refresh_token || '');
  if (!refreshToken) {
    return jsonResponse(401, { error: 'invalid_session' }, corsHeaders);
  }

  try {
    const refreshResp = await refreshSession({ supabaseUrl, anonKey, refreshToken });
    if (refreshResp.error || !refreshResp.data || !refreshResp.data.user) {
      return jsonResponse(401, { error: 'invalid_session' }, corsHeaders);
    }

    const profileResp = await getProfileByUserId({
      supabaseUrl,
      serviceRoleKey,
      userId: refreshResp.data.user.id,
    });
    if (profileResp.error || !profileResp.data) {
      return jsonResponse(403, { error: 'access_denied' }, corsHeaders);
    }

    const acesso = await checkMeshAccess({
      supabaseUrl,
      serviceRoleKey,
      userId: profileResp.data.id,
    });
    if (!acesso.allowed) {
      return jsonResponse(403, { error: accessErrorCode(acesso.reason) }, corsHeaders);
    }

    return jsonResponse(
      200,
      {
        session: {
          access_token: refreshResp.data.access_token,
          refresh_token: refreshResp.data.refresh_token,
          expires_in: refreshResp.data.expires_in,
          expires_at: refreshResp.data.expires_at,
          token_type: refreshResp.data.token_type,
        },
        user: {
          id: refreshResp.data.user.id,
          email: refreshResp.data.user.email,
        },
        profile: profileResp.data,
      },
      corsHeaders
    );
  } catch (_) {
    return jsonResponse(500, { error: 'internal_error' }, corsHeaders);
  }
};
