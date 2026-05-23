# mexe

mexe is a PWA (Progressive Web App) for field task navigation integrated with AgroXeque authentication.

> Note: The active authentication flow uses Supabase via `/api/auth/*`.

## Overview

- PWA installable on mobile and desktop
- Interactive map with Leaflet
- Task loading from GeoJSON (`.frs`, `.agxq`, `.geojson`, `.json`)
- GPS positioning and navigation path recording
- Offline-first behavior using Service Worker
- Authentication with email/password and Google OAuth
- User type validation on the server side

## Authentication Flow

1. User signs in from the app.
2. App calls internal endpoints under `/api/auth/*`.
3. Backend validates user credentials in Supabase Auth.
4. Backend validates eligibility from `public.profiles`.
5. Session is persisted in IndexedDB via LocalForage.

Session storage includes non-sensitive user and session metadata. Passwords are never stored locally.

## Project Structure

```text
xeque-map-sem-ofusc_backup-main/
+-- index.html
+-- styles.css
+-- scripts.js
+-- auth.js
+-- sw.js
+-- oauth-callback.html
+-- manifest.json
+-- server.js
+-- start-server.bat
+-- start-server.ps1
+-- netlify.toml
+-- netlify/functions/
+-- supabase/
+-- icons/
+-- imagens/
+-- libs/
```

## Local Development

### Start local server

```bash
node server.js
```

Or on Windows:

```bat
start-server.bat
```

```powershell
.\start-server.ps1
```

### Access app

Open:

`http://localhost:8080`

## Deployment

- Recommended target: Netlify
- Auth endpoints are routed via `netlify.toml` to Netlify Functions
- Keep all sensitive values in environment variables (`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `CORS_ALLOWED_ORIGINS`)

## Security Notes

- Never commit secrets to source control
- Restrict CORS to official domains only
- Use HTTPS in production
- Keep dependencies and runtime patched
- Monitor auth endpoints and rate-limits

## Troubleshooting

### Sign-in fails

1. Ensure local server is running.
2. Inspect browser console and network tab.
3. Verify environment variables are configured.
4. Check Netlify Function or local server logs.

### Session does not persist

1. Inspect IndexedDB storage in browser devtools.
2. Verify session expiration timestamps.
3. Confirm Service Worker behavior is not stale.

### Error 503

1. Confirm backend/auth endpoints are reachable.
2. Verify routing/proxy configuration in `netlify.toml`.
3. Check function logs for upstream errors.

## License

Proprietary software owned by AgroXeque.
