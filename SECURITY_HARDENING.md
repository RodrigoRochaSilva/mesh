# Security Hardening Roadmap (mesh)

This document consolidates security hardening recommendations before production rollout.

## Goals

- Reduce attack surface
- Improve abuse prevention and incident response
- Strengthen auth/session controls

## P0 (Required Before Production)

1. Backend privilege isolation
- Minimize `service_role` usage
- Prefer narrowly scoped SQL functions/RPCs
- Review grants and role permissions regularly

2. Secret management
- Keep secrets only in provider environment variables
- Block secrets in source control and logs

3. Production-grade rate limiting
- Replace in-memory rate limiter with distributed storage (Redis/KV/Edge)
- Enforce limits by IP + identity + sensitive route

4. Strict CORS/origin controls
- Set `CORS_ALLOWED_ORIGINS` to official domains only
- Avoid wildcards in production
- Validate host/origin on auth endpoints

5. XSS and session exposure protection
- Enforce strong CSP where possible
- Sanitize/escape dynamic content
- Minimize third-party scripts and add SRI where applicable

6. Safe logging
- Never log passwords, tokens, cookies, or sensitive payloads

## P1 (Shortly After Go-Live)

1. Observability and alerting
- Centralize auth logs
- Add alerts for auth failure spikes and unusual behavior

2. Session policy review
- Keep periodic online revalidation
- Reassess offline window and grace period with real metrics

3. Automated security tests
- Regression tests for password and Google OAuth flows
- Authorization tests for invalid/inactive/expired plans

4. Dependency hardening
- Maintain regular vulnerability review and patch cycle

## P2 (Structural Evolution)

1. Architectural segmentation
- Evaluate isolating scouting auth/authorization in a lower blast-radius service

2. Advanced abuse detection
- Consider lightweight device fingerprinting (regulatory caution)
- Detect anomalous account/geo/IP patterns

3. Incident response readiness
- Document key rotation and session revocation playbooks
- Run periodic tabletop exercises

## Production Checklist

- [ ] Secrets rotated and inventoried
- [ ] CORS restricted to official domains
- [ ] OAuth redirect URLs minimized and reviewed
- [ ] Monitoring and alerts active
- [ ] Credential rotation procedure documented

## Production Security Readiness

Environment is considered security-ready when all P0 items are completed and validated in staging with evidence from testing and monitoring.
