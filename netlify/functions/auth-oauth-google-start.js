'use strict';

const {
  getEnvConfig,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
  parseBody,
  buildGoogleAuthorizeUrl,
  isValidPkceChallenge,
  isSafeRedirectPath,
} = require('./_authCommon');

exports.handler = async (event) => {
  const { supabaseUrl, anonKey, oauthRedirectPath, allowedOrigins } = getEnvConfig();
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

  if (!supabaseUrl || !anonKey) {
    return jsonResponse(500, { error: 'server_misconfigured' }, corsHeaders);
  }

  const body = parseBody(event.body);
  if (body === null) return jsonResponse(400, { error: 'invalid_json' }, corsHeaders);

  const codeChallenge = String((body && body.code_challenge) || '');
  if (!isValidPkceChallenge(codeChallenge)) {
    return jsonResponse(400, { error: 'invalid_code_challenge' }, corsHeaders);
  }

  const requestedRedirect = (body && body.redirect_path) ? String(body.redirect_path) : '';
  const defaultRedirect = oauthRedirectPath || '/oauth-callback.html';
  const redirectPath = requestedRedirect && isSafeRedirectPath(requestedRedirect)
    ? requestedRedirect
    : defaultRedirect;

  const forwardedProto = String(event.headers['x-forwarded-proto'] || 'https');
  const host = String(event.headers.host || '');
  const inferredOrigin = host ? `${forwardedProto}://${host}` : '';
  const requestOrigin = origin || inferredOrigin;
  const redirectTo = `${requestOrigin}${redirectPath}`;

  const authorizeUrl = buildGoogleAuthorizeUrl({
    supabaseUrl,
    redirectTo,
    codeChallenge,
  });

  return jsonResponse(
    200,
    {
      provider: 'google',
      authorize_url: authorizeUrl,
      redirect_to: redirectTo,
    },
    corsHeaders
  );
};
