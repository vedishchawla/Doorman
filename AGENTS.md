Project: Zero-Trust Identity-Aware Ingress Proxy (Go 1.22).
Packages match the architecture modules: cmd/proxy, internal/auth (OIDC), internal/policy (OPA client), internal/mtls, internal/audit, internal/posture, internal/config.
Stack: Keycloak, OPA with Rego over REST, Docker Compose, Prometheus, k6.
Rules: standard library first, small packages, unit tests for every package, config from env vars, JSON logs, fail closed on any auth or policy error.
Request flow: request, OIDC auth, token validation, policy evaluation, decision, mTLS to backend, response, async audit log. Log the step number in audit entries.
Target: p95 added latency under 12 ms with the OPA decision cache on.
Every task: write a plan first, change only what was asked, run tests, then list what changed and what is untested. Never add unrequested features.