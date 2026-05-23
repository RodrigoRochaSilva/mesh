'use strict';

const {
  getEnvConfig,
  buildCorsHeaders,
  isOriginAllowed,
  jsonResponse,
} = require('./_authCommon');

exports.handler = async (event) => {
  const { allowedOrigins } = getEnvConfig();
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

  return jsonResponse(200, { ok: true }, corsHeaders);
};
