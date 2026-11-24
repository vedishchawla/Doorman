# Doorman — Complete Project Guide (Simple Language + Real Examples)

> **One-line summary:** Doorman is a **Zero-Trust Security Guard ("Doorman")** that sits in front of your backend microservices. Before letting *any* request touch a backend, it checks **who you are**, **whether your laptop is healthy/secure**, and **whether the rules allow it** — and does all of this in **under 12 milliseconds**.

---

## 1. Why Does This Project Exist? (The Simple Analogy)

In old-fashioned security ("Castle & Moat" or VPN):
- Once you enter the office building (or connect to the VPN), everyone trusts you automatically.
- If a hacker steals one employee's password or plugs in an infected laptop, they can freely talk to every internal server.

**Zero-Trust** says: **"Never Trust, Always Verify"** — on **every single request**.

Think of **Doorman** like a strict security guard at a high-security bank vault:
1. **Show your Government ID** *(Keycloak OIDC Login Token)* — "Are you really Alice?"
2. **Show your Device Health Certificate** *(ES256 Device Posture Token)* — "Is your laptop's hard drive encrypted, is your firewall on, and was your OS updated in the last 30 days?"
3. **Check the Rulebook** *(Open Policy Agent / OPA Rego)* — "Is Alice allowed to open this specific door, from this country, at this time of day?"
4. **Use an Armored Tunnel** *(Mutual TLS / mTLS)* — Even after passing the guard, the backend vault refuses to talk to anyone except the guard carrying an official secret certificate.
5. **Write in the Security Register** *(Async Audit Log)* — Every allowed or blocked attempt is written down with the exact reason and timing.

---

## 2. All Moving Parts Explained Simply

| Part | Folder / File | What It Does in Plain English |
|---|---|---|
| **Nginx** | `nginx/nginx.conf` | The front door on port `443` (HTTPS). Terminates the user's encrypted browser/CLI connection and hands the request to Doorman. |
| **Doorman Proxy** | `cmd/proxy/` & `internal/*` | The brain of the project (written in **Go 1.22**). Runs the 7 security checks and decides `ALLOW` or `DENY`. Fails closed (if anything breaks, it blocks traffic). |
| **Keycloak** | `keycloak/realm-export.json` | The ID card issuer (OIDC Identity Provider). Holds users (`alice` with `admin` role, `bob` with `viewer` role) and signs JWT login tokens (`RS256`). |
| **Posture Agent** | `cmd/posture-agent/main.go` | A small client tool that inspects the laptop (disk encryption, firewall, OS patch age) and signs a tamper-proof `ES256` health token. |
| **OPA (Open Policy Agent)** | `policies/authz.rego` & `policies/data.json` | The rule engine on port `8181`. Reads simple rules (`authz.rego`) + allowed countries (`data.json`) and returns `allow: true/false` + exact denial reason. |
| **Backend A & B** | `backends/main.go` | Two protected Go microservices. They **refuse normal HTTP/HTTPS** — they only respond over **mTLS**, where Doorman also proves its own client certificate. |
| **SecOps Dashboard** | `dashboard/` | The React + TypeScript control panel on port `3000` where you can inspect the 7 gates, fire real requests, test Rego rules, view benchmarks, read audit logs, and inspect Docker/Kubernetes status. |
| **Docker & Kubernetes** | `Dockerfile`, `docker-compose.yml`, `k8s/` | Packages everything into lightweight containers (Docker) and production cloud orchestration with autoscaling and pod firewalls (Kubernetes). |

### Inside `internal/` (Small Modular Go Packages)
- `internal/config`: Reads all settings cleanly from environment variables (`OPA_URL`, `OIDC_ISSUER_URL`, `MTLS_CA_FILE`, etc.).
- `internal/auth`: Downloads Keycloak's public keys (JWKS), caches them, and verifies JWT signatures so nobody can fake a login token.
- `internal/posture`: Checks the `ES256` cryptographic signature on the `X-Device-Posture` header.
- `internal/policy`: Calls OPA over REST and caches decisions in memory so repeated checks take `< 1 ms`.
- `internal/mtls`: Connects to `backend-a` / `backend-b` using short-lived client certificates (`proxy-client.crt`) that hot-reload automatically without restarting the proxy.
- `internal/audit`: Writes JSON log lines to `audit-logs/audit.jsonl` in the background + exposes Prometheus metrics on `:9090`.

---

## 3. The Complete 7-Step Request Flow

```text
User / CLI
  │  HTTPS (:443)
  │  Headers: Authorization: Bearer <Keycloak JWT>
  │           X-Device-Posture: <ES256 Posture Token>
  ▼
[Step 1] Nginx Edge ──► Doorman Proxy (:8080)
  │
  ▼
[Step 2] OIDC Auth (internal/auth) ──► Valid Keycloak JWT?
  │        No  ──► 401 Unauthorized (STOP)
  │        Yes ▼
[Step 3] Device Posture (internal/posture) ──► Valid ES256 Signature?
  │        No  ──► 403 Forbidden: invalid-posture-token (STOP)
  │        Yes ▼
[Step 4] OPA Policy (internal/policy) ──► Check policies/authz.rego
  │        (Geo, Disk, Firewall, Patch Age, Role, Method, Path, Time)
  ▼
[Step 5] Fail-Closed Decision Gate (cmd/proxy)
  │        allow != true or error ──► 403 Forbidden + policy_id (STOP)
  │        allow == true          ▼
[Step 6] mTLS Upstream (internal/mtls) ──► Backend A or Backend B
  │        (Mutual TLS 1.3 + verified X-User / X-Roles headers)
  ▼
[Step 7] Async Audit & Metrics (internal/audit)
           Writes audit-logs/audit.jsonl + updates Prometheus :9090
```

---

## 4. Five Concrete Examples (Step-by-Step Walkthrough)

### Example 1: Happy Path — Alice Accesses `backend-a` (`200 OK`)

**Who:** `alice` (role: `admin`)  
**Device:** Disk encrypted (`true`), Firewall on (`true`), OS patched `5` days ago (`<= 30`)  
**Location & Time:** Country `IN` (India, in allowlist), `14:00`  
**Request:** `GET https://localhost/backend-a/`

1. **Step 1 (Ingress):** Nginx terminates TLS on `:443` and forwards the request + headers to Doorman on `:8080`.
2. **Step 2 (OIDC Auth):** `internal/auth` verifies the `Authorization: Bearer ...` JWT using Keycloak's cached public key. Extracts `user = "alice"`, `roles = ["admin"]`. *(~0.2 ms)*
3. **Step 3 (Posture):** `internal/posture` verifies the `X-Device-Posture` ES256 signature using `POSTURE_PUBLIC_KEY`. Trusts the claims: `disk_encrypted: true`, `firewall_on: true`, `os_patch_age_days: 5`. *(~0.1 ms)*
4. **Step 4 (OPA Policy):** `internal/policy` checks OPA (`zt.authz`).
   - Is `IN` in `allowed_countries`? Yes.
   - Disk encrypted? Yes. Firewall on? Yes. Patch age `<= 30`? Yes (`5 <= 30`).
   - Role `admin`? Yes — admins can use any method and path.
   - Result: `{ "allow": true, "policy_id": "", "reason": "" }`.
5. **Step 5 (Gate):** `allow == true` -> Gate opens!
6. **Step 6 (mTLS):** Doorman strips any fake client `X-User` headers, injects verified `X-User: alice` and `X-Roles: admin`, and opens an mTLS 1.3 connection using `proxy-client.crt` to `backend-a:8080`. `backend-a` replies **`200 OK`**.
7. **Step 7 (Audit):** Background worker logs `step: 6, decision: "allow"` to `audit-logs/audit.jsonl` and increments Prometheus latency histograms.

---

### Example 2: Compromised Laptop — Alice With Unencrypted Disk (`403 Forbidden`)

**Who:** `alice` (she has the **real password** and a **valid `admin` token**!)  
**Device:** Generated with `go run ./cmd/posture-agent --unhealthy` (`disk_encrypted: false`)  
**Request:** `GET https://localhost/backend-a/`

- **Steps 1–3:** Pass! Alice's login is real, and the posture token signature is real (nobody faked it — her laptop genuinely reported an unencrypted disk).
- **Step 4 (OPA):** Rule in `policies/authz.rego` triggers:
  ```rego
  denials contains {"rule_id": "disk-not-encrypted", "message": "Denied: device is not compliant: disk is not encrypted"} if {
      input.device_posture.disk_encrypted == false
  }
  ```
- **Step 5 (Gate):** Blocks immediately with **`403 Forbidden`**:
  ```json
  {
    "error": "forbidden",
    "policy_id": "disk-not-encrypted",
    "reason": "Denied: device is not compliant: disk is not encrypted"
  }
  ```
- **Step 6:** Skipped! `backend-a` **never sees the request**.
- **Step 7:** Logged in `audit.jsonl` with `step: 4, decision: "deny", policy_id: "disk-not-encrypted"`.

> **Why this matters:** Even if an admin's account is valid, an insecure device cannot touch production workloads.

---

### Example 3: Least-Privilege RBAC — Bob (`viewer`) Tries `/admin` or `POST` (`403 Forbidden`)

**Who:** `bob` (role: `viewer`)  
**Device:** Healthy (`disk_encrypted: true`, `firewall_on: true`, `5` days old)  
**Scenario A:** Bob tries `GET /backend-a/admin` -> blocked with `viewer-admin-path` (`Denied: viewer cannot access /admin paths`).  
**Scenario B:** Bob tries `POST /backend-a/` -> blocked with `viewer-method-denied` (`Denied: viewer cannot use method POST`).  
**Scenario C:** Bob tries `GET /backend-a/` at `22:00` (10 PM) -> blocked with `viewer-time-restricted` (`Denied: viewer access outside business hours 09:00-19:00`).

> **Why this matters:** A read-only user can only read (`GET`/`HEAD`/`OPTIONS`) non-admin routes during office hours (`09:00–19:00`).

---

### Example 4: Attacker Without Login Token (`401 Unauthorized`)

**Request:** `curl -k https://localhost/backend-a/` (no `Authorization` header)

- **Step 1:** Arrives at Doorman.
- **Step 2 (`internal/auth`):** Missing or invalid Bearer token -> immediately returns **`401 Unauthorized`** (or redirects to Keycloak login in a browser).
- **Steps 3–6:** Never run.
- **Step 7:** Logged with `step: 1` or `2`, `decision: "deny"`.

---

### Example 5: Browser Login Without Posture Agent (`403 Forbidden`)

If you open `https://localhost/` in Chrome and log in as `alice`:
- Keycloak authenticates you (Step 2 passes!).
- **Step 3 (`internal/posture`)** sees there is **no `X-Device-Posture` header** (because a normal browser doesn't run `posture-agent`).
- Doorman fails closed with **`403 Forbidden`**:
  ```json
  {
    "error": "forbidden",
    "policy_id": "invalid-posture-token",
    "reason": "invalid device posture token: missing posture token"
  }
  ```

---

## 5. How Performance Stays Under 12 ms (Caching + Async Logs)

Checking OIDC + Posture + OPA on every request could be slow if done naively:
- **Problem:** Calling OPA over HTTP on every request takes `13.80 ms` (10 users) to **`29.10 ms`** (100 concurrent users) — violating the `< 12 ms` SLA.
- **Solution 1 — OPA Decision Cache (`internal/policy`):** Doorman caches `(user + roles + method + path + geo + posture)` decisions in memory for a short TTL. Repeated requests hit RAM in `< 1 ms`, keeping total p95 latency between **`7.34 ms` (10 VUs)** and **`11.85 ms` (100 VUs)** at **`7,820 requests/sec`**. (Errors are *never* cached!)
- **Solution 2 — JWKS Key Caching (`internal/auth`):** Keycloak's public keys are cached in memory instead of fetched per request.
- **Solution 3 — Async Audit Worker (`internal/audit`):** Writing JSON lines to disk happens on a separate background goroutine via a buffered channel so disk I/O never slows down the user's HTTP response.

---

## 6. Docker & Kubernetes (Cloud-Native DevOps Architecture)

### Docker (`Dockerfile` + `docker-compose.yml`)
1. **Multi-Stage Distroless Build (`Dockerfile`):**
   - Stage 1 compiles the Go binary statically (`CGO_ENABLED=0`).
   - Stage 2 copies *only* the binary into `gcr.io/distroless/static-debian12:nonroot` (no `bash`, no `curl`, no `apt` — tiny image, minimal CVEs, runs as non-root).
2. **Bridge Network & Healthchecks (`docker-compose.yml`):**
   - All 6 services run on `zt-net` with `depends_on: condition: service_healthy`, ensuring `proxy` only starts after `keycloak`, `backend-a`, and `backend-b` are healthy.

### Kubernetes (`k8s/`)
Designed for production cloud deployment in the `doorman` namespace:
1. **`01-configmaps.yaml`:** Stores `authz.rego`, `data.json`, and `nginx.conf` declaratively so policies can be updated without rebuilding Go binaries.
2. **`05-proxy.yaml` (Security + Autoscaling):**
   - Runs `doorman-proxy` as non-root (`UID 65532`), `readOnlyRootFilesystem: true`, all Linux capabilities dropped.
   - Configures readiness & liveness probes (`/proxy --healthcheck`) and Prometheus scraping on `:9090`.
   - Includes a **`HorizontalPodAutoscaler` (`doorman-proxy-hpa`)** that automatically scales proxy pods from **2 to 10 replicas** if CPU crosses 70%.
3. **`07-network-policies.yaml` (Pod-Level Firewall):**
   - `default-deny-ingress` blocks **all** pod-to-pod traffic inside `doorman` by default.
   - Explicit allow rules permit *only* `nginx-ingress -> doorman-proxy -> (opa, keycloak, backend-a, backend-b)`.
   - **Double Isolation:** Even if someone compromises another pod in the cluster, both Kubernetes `NetworkPolicy` (L3/L4) **and** mTLS (L7) block them from reaching `backend-a` or `backend-b`.

---

## 7. Quick Demo Commands & Viva Cheat Sheet

### Start Everything for Demo
```bash
# 1. Start the 6 Docker containers (if not already running)
make up
make test

# 2. Start the frontend console (http://localhost:3000)
cd dashboard && npm run dev
```

### Run Unit Tests
```bash
go test -v ./...            # Backend Go unit tests
cd dashboard && npm test    # Frontend policy logic tests
```

### Viva Questions & Short Answers

1. **What does "Fail-Closed" mean in your project?**  
   *Answer:* If anything goes wrong — missing token, bad signature, OPA unreachable, or unknown role — Doorman defaults to **Deny (401/403)**. It never accidentally allows traffic through on error.
2. **Why do you use both Keycloak and OPA?**  
   *Answer:* Keycloak handles **Authentication** ("Who are you?"), while OPA handles **Authorization** ("What are you allowed to do given your device health, role, country, and time?").
3. **Why sign the device posture with ES256 instead of trusting a plain JSON header?**  
   *Answer:* Without an ECDSA P-256 signature, any attacker could send `X-Device-Posture: {"disk_encrypted":true}` with `curl` and fake compliance. ES256 proves the posture report came from the trusted agent.
4. **How do you guarantee backends can't be bypassed?**  
   *Answer:* In Docker, `backend-a` and `backend-b` aren't exposed to host ports and enforce mTLS client certificates. In Kubernetes, `default-deny-ingress` NetworkPolicies allow traffic *only* from `doorman-proxy` pods.
5. **How did you achieve `< 12 ms` p95 latency?**  
   *Answer:* Using Go's lightweight concurrency, cached Keycloak JWKS keys, an in-memory TTL decision cache for OPA (`29.10 ms` -> `11.85 ms` at 100 VUs), and non-blocking async audit logging.
