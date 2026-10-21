# Doorman – Zero-Trust Identity-Aware Ingress Proxy

A Go 1.22 reverse proxy that authenticates every request via OIDC
(Keycloak), authorises it through OPA policy evaluation, and forwards
it to a backend over mTLS.  All decisions are audit-logged with
step numbers.

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- Go 1.22+ (for local development)
- `openssl` (for TLS cert generation)

### Host Entry

Add the following line to `/etc/hosts` so that the browser and
containers share the same Keycloak issuer URL
(`http://keycloak:8080/realms/zt`):

```
127.0.0.1  keycloak
```

### Start the Stack

```bash
make up      # generates TLS certs, builds images, starts containers
make test    # shows container status and smoke-tests each service
make down    # tears everything down
```

### Security Operations Dashboard

```bash
cd dashboard
npm install   # or bun install
npm run dev   # runs console at http://localhost:3000
```

### Default Credentials

| Service  | Username | Password | Notes                        |
|----------|----------|----------|------------------------------|
| Keycloak | admin    | admin    | Admin console                |
| alice    | alice    | alice    | Realm `zt`, role `admin`     |
| bob      | bob      | bob      | Realm `zt`, role `viewer`    |

**Client:** `zt-proxy` (confidential, secret: `zt-proxy-dev-secret`)

### Ports

| Service    | Host Port | Purpose                       |
|------------|-----------|-------------------------------|
| nginx      | 443       | TLS-terminating entry point   |
| Keycloak   | 8080      | OIDC provider (HTTP)          |
| Keycloak   | 9000      | Management / health endpoint  |
| OPA        | 8181      | Policy engine REST API        |

### Health Checks

| Service    | Method         | Command                              |
|------------|----------------|---------------------------------------|
| Keycloak   | Host (curl)    | `curl http://localhost:9000/health/ready` |
| OPA        | Host (curl)    | `curl http://localhost:8181/health`       |
| nginx      | Container (nc) | built-in Docker healthcheck              |
| backend-*  | Container (binary) | `/backend healthcheck` (Docker healthcheck) |

## Project Layout

```
cmd/proxy/            # Entry point for the proxy (Step 2+)
internal/
  auth/               # OIDC token validation
  policy/             # OPA client
  mtls/               # mTLS dialer for backends
  audit/              # Async audit logger
  posture/            # Device posture checks
  config/             # Env-var config loader
backends/             # Dummy echo backends (Go)
keycloak/             # Realm export for import
nginx/                # TLS-terminating reverse proxy config
  certs/              # Generated self-signed certs (git-ignored)
policies/             # OPA Rego policies
```

### Device Posture

Generate a five-minute ES256 posture token with the posture agent:

```sh
go run ./cmd/posture-agent > posture.token 2> posture-key.txt
```

Set the public key printed by the agent as `POSTURE_PUBLIC_KEY` on the proxy,
then send the token in the `X-Device-Posture` header. Use
`go run ./cmd/posture-agent --unhealthy` to generate an unhealthy demo token.
The proxy verifies the signature and expiry before including the verified
claims in the OPA policy input. Posture verification is required by default.
For Compose, put the public key in the ignored `.env` file as
`POSTURE_PUBLIC_KEY='...'`; the Compose configuration refuses to start if it
is missing.

The Compose demo uses `DEV_DEFAULT_COUNTRY=IN`; this is a fixed development
default, not a client geolocation lookup.

### Audit and Metrics

Requests are written as JSON lines to `AUDIT_LOG_FILE` (Compose uses
`/var/log/doorman/audit.jsonl`, mounted from the ignored `audit-logs/`
directory). Entries include request identity, decision, policy, device ID,
step, and auth/OPA/upstream latency. Tokens, cookies, posture headers, and
query strings are never recorded.

Prometheus metrics are available on the separate proxy metrics listener:

```sh
curl http://localhost:9090/metrics
```

The recent audit API is restricted to authenticated users with the `admin`
role:

```sh
curl -H "Authorization: Bearer <alice-token>" \
  'https://localhost/api/audit?decision=deny'
```

### Internal mTLS

Generate the short-lived internal CA, proxy client certificate, and backend
server certificates with:

```sh
scripts/gen-certs.sh
```

The proxy uses `MTLS_CA_FILE`, `MTLS_CLIENT_CERT_FILE`, and
`MTLS_CLIENT_KEY_FILE` to authenticate to TLS-enabled backends. The transport
reloads those files when they change. Both backends require a client
certificate signed by the generated CA. When the generated server certificates
are rotated, restart both backend containers so they reload their certificates;
the proxy does not need to restart.
