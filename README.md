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
