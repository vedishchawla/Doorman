# Doorman – Zero-Trust Identity-Aware Ingress Proxy

A Go 1.22 identity-aware reverse proxy implementing a Zero-Trust security model. Every request is authenticated via OpenID Connect (Keycloak), evaluated against declarative Open Policy Agent (OPA) policies including hardware posture verification (ES256), and forwarded to upstream microservices over mutual TLS (mTLS). All decisions are recorded in an asynchronous audit log with step tracking and Prometheus latency metrics.

---

## Architecture Overview

```
                                  +-------------------+
                                  | Keycloak (OIDC)   |
                                  | RS256 Auth Server |
                                  +---------+---------+
                                            | (2)
                                            v
+-------------+  HTTPS (1)   +----------------------------+  mTLS (6)   +-------------------+
| User/Client | ------------>|    Doorman Ingress Proxy   | ----------->| Backend Services  |
| Browser/CLI |              | (cmd/proxy / internal/...) |             | (Go HTTP Echo)    |
+-------------+              +--------------+-------------+             +-------------------+
                                            | (4)
                                            v
                                  +-------------------+
                                  |     OPA Engine    |
                                  |  (Rego / REST)    |
                                  +-------------------+
```

### The 7-Step Verification Pipeline

| Step | Stage | Module | Description |
|---|---|---|---|
| **Step 1** | Request Ingress | `nginx / cmd/proxy` | TLS terminated; Bearer token and `X-Device-Posture` header extracted. |
| **Step 2** | OIDC Authentication | `internal/auth` | Keycloak JWT signature verified against JWKS keys; username and roles extracted. |
| **Step 3** | Device Posture & Geo | `internal/posture` | ES256 posture token verified against public key (disk encryption, firewall, patch age). |
| **Step 4** | OPA Policy Evaluation | `internal/policy` | Context-aware Rego evaluation (`zt.authz`) with in-memory decision caching. |
| **Step 5** | Decision Gate | `cmd/proxy` | Fail-closed gate: allowed requests proceed; denials return HTTP 403 with specific reason. |
| **Step 6** | mTLS Upstream Forwarding | `internal/mtls` | Mutual TLS transport forward to Backend A/B with short-lived client certificates. |
| **Step 7** | Async Audit & Metrics | `internal/audit` | Request state dispatched to asynchronous worker for `audit.jsonl` and Prometheus `:9090`. |

---

## Quick Start

### 1. Prerequisites

- Docker & Docker Compose v2
- Go 1.22+ (for local development & posture agent)
- Node.js 18+ (for frontend dashboard)
- `openssl` (for mTLS certificate generation)

### 2. Host Entry

Add `keycloak` to `/etc/hosts` so browser redirects and container communication share the same issuer endpoint (`http://keycloak:8080/realms/zt`):

```bash
sudo sh -c 'echo "127.0.0.1  keycloak" >> /etc/hosts'
```

### 3. Start the Backend Stack

```bash
make up      # generates mTLS certs, builds images, starts containers
make test    # verifies health checks and runs smoke tests
make down    # stops containers and tears down networks
```

### 4. Start the Security Operations Dashboard

```bash
cd dashboard
npm install   # or bun install
npm run dev   # console runs at http://localhost:3000
```

---

## Default Credentials & Roles

| Service | Username | Password | Role / Details |
|---|---|---|---|
| **Keycloak Admin** | `admin` | `admin` | Admin Console (`http://localhost:8080`) |
| **Alice** | `alice` | `alice` | Realm `zt`, Role `admin` (Full access to all methods and paths) |
| **Bob** | `bob` | `bob` | Realm `zt`, Role `viewer` (Read-only `GET`/`HEAD`/`OPTIONS`, business hours, no `/admin`) |

* **Client ID:** `zt-proxy` (confidential, secret: `zt-proxy-dev-secret`)

---

## Service Endpoints & Ports

| Service | Port | Protocol / Purpose |
|---|---|---|
| **Nginx Ingress** | `443` | TLS entry point forwarding to Doorman proxy |
| **Doorman Proxy** | `8080` | Core reverse proxy HTTP listener |
| **Proxy Metrics** | `9090` | Prometheus `/metrics` endpoint |
| **Keycloak OIDC** | `8080` / `9000` | OpenID Connect auth provider & management health |
| **Open Policy Agent** | `8181` | REST policy evaluation engine (`/v1/data/zt/authz`) |
| **Backend A & B** | `8082` / `8083` | Echo backends enforcing client certificate mTLS |
| **Security Dashboard** | `3000` | React/Vite/Tailwind SecOps console |

---

## Verification & Testing Workflows

### A. Testing via Web Browser
1. Open `https://localhost/` in your browser.
2. Accept the self-signed certificate warning (`Advanced -> Proceed to localhost`).
3. You will be redirected to the Keycloak login screen.
4. Log in as `alice` (`password: alice`).
5. Because standard browsers do not send an `X-Device-Posture` header, the proxy enforces Zero-Trust device compliance and returns:
   ```json
   {
     "error": "forbidden",
     "policy_id": "invalid-posture-token",
     "reason": "invalid device posture token: missing posture token"
   }
   ```
6. Open the Dashboard at `http://localhost:3000` and navigate to **Audit Log** to inspect your live request trace.

### B. Testing Full End-to-End Flow via CLI
To complete all 7 steps including device posture verification:

```bash
# 1. Generate compliant ES256 posture token
POSTURE_TOKEN=$(go run ./cmd/posture-agent)

# 2. Authenticate as alice and obtain JWT access token
ACCESS_TOKEN=$(curl -s -d "client_id=zt-proxy" \
  -d "client_secret=zt-proxy-dev-secret" \
  -d "username=alice" \
  -d "password=alice" \
  -d "grant_type=password" \
  http://localhost:8080/realms/zt/protocol/openid-connect/token | jq -r .access_token)

# 3. Send request with both Identity and Device Posture headers
curl -k \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Device-Posture: $POSTURE_TOKEN" \
  https://localhost/backend-a/
```

### C. Testing Unhealthy Device Posture Demo
Simulate a compromised machine (unencrypted disk / disabled firewall):

```bash
UNHEALTHY_TOKEN=$(go run ./cmd/posture-agent --unhealthy)

curl -k \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Device-Posture: $UNHEALTHY_TOKEN" \
  https://localhost/backend-a/
```
The request will be rejected by OPA with `Denied: device is not compliant: disk is not encrypted`.

---

## Performance Target & Benchmarks

* **SLA Objective:** Added latency under **12 ms (p95)** with OPA decision caching enabled.
* **Benchmark Data:** Loaded from `bench/results.csv` and visualized on the dashboard:
  * **With OPA Cache ON:** p95 latency remains between **7.34 ms (10 VUs)** and **11.85 ms (100 VUs)**.
  * **With OPA Cache OFF:** Repeated REST roundtrips push p95 latency to **13.80 ms – 29.10 ms**.
  * **Throughput:** Proxy scales past **7,800 requests/second** on standard hardware.

---

## Project Layout

```
.
├── cmd/
│   ├── proxy/              # Core proxy entrypoint and routing middleware
│   └── posture-agent/      # Client CLI generating signed ES256 posture JWTs
├── internal/
│   ├── auth/               # OIDC validation, JWKS caching, and session management
│   ├── policy/             # OPA REST client with in-memory decision cache
│   ├── posture/            # ES256 posture token signature and claims verification
│   ├── mtls/               # Dynamic mTLS dialer with hot-reloading 24-hour certs
│   ├── audit/              # Async JSON-lines logger and Prometheus metrics
│   └── config/             # Environment variable configuration loader
├── dashboard/              # React + Vite + Tailwind SecOps dashboard
│   ├── src/pages/          # Overview, Audit Log, Policy Tester, Benchmarks, About
│   └── src/api.ts          # API client and local OPA Rego evaluation sandbox
├── backends/               # Echo microservices requiring client certificate mTLS
├── policies/
│   ├── authz.rego          # OPA Rego rules (geo, posture, roles, business hours)
│   └── data.json           # Country allowlist data document
├── bench/
│   └── results.csv         # Benchmark throughput and percentile latency data
├── scripts/
│   └── gen-certs.sh        # Generates internal CA, proxy client, and backend certs
├── nginx/                  # TLS termination reverse proxy configuration
└── docker-compose.yml      # Multi-container service definitions
```

---

## Testing & Quality Assurance

Run the Go backend test suite:
```bash
go test -v ./...
```

Run the Dashboard test suite and production build:
```bash
cd dashboard
npm test
npm run build
```
