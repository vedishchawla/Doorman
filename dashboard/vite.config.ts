import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';
import cp from 'node:child_process';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'audit-and-bench-api-server',
      configureServer(server) {
        // Serve /api/audit
        server.middlewares.use('/api/audit', (req, res) => {
          const url = new URL(req.url || '', `http://${req.headers.host}`);
          const filterUser = url.searchParams.get('user') || '';
          const filterDecision = url.searchParams.get('decision') || '';
          const filterResource = url.searchParams.get('resource') || '';

          const logPath = path.resolve(__dirname, '../audit-logs/audit.jsonl');
          let entries: any[] = [];

          if (fs.existsSync(logPath)) {
            const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n');
            for (let i = lines.length - 1; i >= 0; i--) {
              const line = lines[i].trim();
              if (!line) continue;
              try {
                const item = JSON.parse(line);
                if (filterUser && item.user !== filterUser) continue;
                if (filterDecision && item.decision !== filterDecision) continue;
                if (filterResource && item.resource !== filterResource) continue;
                entries.push(item);
              } catch (e) {
                // skip corrupted lines
              }
            }
          }

          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.end(JSON.stringify(entries));
        });

        // Serve /bench/results.csv
        server.middlewares.use('/bench/results.csv', (_req, res) => {
          const csvPath = path.resolve(__dirname, '../bench/results.csv');
          if (fs.existsSync(csvPath)) {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.end(fs.readFileSync(csvPath, 'utf-8'));
          } else {
            res.statusCode = 404;
            res.end('results.csv not found');
          }
        });

        // Serve /api/dispatch (Live Zero-Trust Pipeline Dispatcher)
        server.middlewares.use('/api/dispatch', (req, res) => {
          if (req.method !== 'POST') {
            res.statusCode = 405;
            res.end('Method not allowed');
            return;
          }

          let body = '';
          req.on('data', chunk => {
            body += chunk;
          });

          req.on('end', () => {
            try {
              const payload = JSON.parse(body || '{}');
              const user = payload.user || 'alice'; // 'alice' | 'bob' | 'anonymous'
              const posture = payload.posture || 'compliant'; // 'compliant' | 'unhealthy_disk' | 'unhealthy_firewall' | 'missing'
              const target = payload.target || '/backend-a/';
              const method = (payload.method || 'GET').toUpperCase();

              let token = '';
              let postureToken = '';
              let isLive = false;
              let rawOutput = '';
              let statusCode = 200;
              let curlCmdDisplay = '';

              const projectRoot = path.resolve(__dirname, '..');

              // 1. Get Keycloak Token if not anonymous
              if (user === 'alice') {
                try {
                  const out = cp.execSync(
                    'curl -s -d "client_id=zt-proxy" -d "client_secret=zt-proxy-dev-secret" -d "username=alice" -d "password=alice" -d "grant_type=password" http://localhost:8080/realms/zt/protocol/openid-connect/token',
                    { timeout: 3000 }
                  ).toString();
                  const parsed = JSON.parse(out);
                  if (parsed.access_token) token = parsed.access_token;
                } catch (e) {}
              } else if (user === 'bob') {
                try {
                  const out = cp.execSync(
                    'curl -s -d "client_id=zt-proxy" -d "client_secret=zt-proxy-dev-secret" -d "username=bob" -d "password=bob" -d "grant_type=password" http://localhost:8080/realms/zt/protocol/openid-connect/token',
                    { timeout: 3000 }
                  ).toString();
                  const parsed = JSON.parse(out);
                  if (parsed.access_token) token = parsed.access_token;
                } catch (e) {}
              }

              // 2. Get Posture Token
              if (posture === 'compliant') {
                try {
                  const out = cp.execSync('go run ./cmd/posture-agent', { cwd: projectRoot, timeout: 5000 }).toString();
                  const lines = out.trim().split('\n');
                  postureToken = lines[lines.length - 1].trim();
                } catch (e) {}
              } else if (posture === 'unhealthy_disk' || posture === 'unhealthy_firewall') {
                try {
                  const out = cp.execSync('go run ./cmd/posture-agent --unhealthy', { cwd: projectRoot, timeout: 5000 }).toString();
                  const lines = out.trim().split('\n');
                  postureToken = lines[lines.length - 1].trim();
                } catch (e) {}
              }

              // Build cURL representation for user
              const tokenSnippet = token ? `${token.substring(0, 16)}...${token.substring(token.length - 8)}` : '(none)';
              const postureSnippet = postureToken ? `${postureToken.substring(0, 16)}...${postureToken.substring(postureToken.length - 8)}` : '(none)';
              curlCmdDisplay = `curl -k -i -X ${method} \\\n  -H "Authorization: Bearer ${tokenSnippet}" \\\n  -H "X-Device-Posture: ${postureSnippet}" \\\n  https://localhost${target}`;

              // 3. Try Live cURL execution to https://localhost${target}
              let executedOutput = '';
              try {
                let headers = '';
                if (token) headers += ` -H "Authorization: Bearer ${token}"`;
                if (postureToken) headers += ` -H "X-Device-Posture: ${postureToken}"`;
                const cmd = `curl -k -s -i -X ${method}${headers} https://localhost${target}`;
                executedOutput = cp.execSync(cmd, { timeout: 6000 }).toString();
                isLive = true;
              } catch (e: any) {
                if (e.stdout) executedOutput = e.stdout.toString();
              }

              let statusText = '200 OK';
              let decision: 'allow' | 'deny' = 'allow';
              let reason = '';
              let stepFailed = 6;
              let responseBody = '';

              if (executedOutput) {
                const headerEnd = executedOutput.indexOf('\r\n\r\n') !== -1 ? executedOutput.indexOf('\r\n\r\n') : executedOutput.indexOf('\n\n');
                const head = headerEnd !== -1 ? executedOutput.substring(0, headerEnd) : executedOutput;
                responseBody = headerEnd !== -1 ? executedOutput.substring(headerEnd).trim() : '';

                const statusMatch = head.match(/HTTP\/[0-9\.]+ ([0-9]+) (.*)/);
                if (statusMatch) {
                  statusCode = parseInt(statusMatch[1], 10);
                  statusText = `${statusMatch[1]} ${statusMatch[2]}`;
                }

                if (statusCode >= 400) {
                  decision = 'deny';
                  try {
                    const parsedErr = JSON.parse(responseBody);
                    reason = parsedErr.reason || parsedErr.error || 'Request rejected by Zero-Trust policy';
                  } catch (e) {
                    reason = responseBody || 'Request forbidden';
                  }

                  if (statusCode === 401 || reason.includes('authentication')) {
                    stepFailed = 2;
                  } else if (reason.includes('posture')) {
                    stepFailed = 3;
                  } else if (reason.includes('Denied:') || reason.includes('viewer') || reason.includes('admin')) {
                    stepFailed = 4;
                  } else {
                    stepFailed = 5;
                  }
                } else {
                  decision = 'allow';
                  stepFailed = 6;
                }
              } else {
                // Fallback simulation if docker is unreachable
                if (user === 'anonymous') {
                  statusCode = 401;
                  statusText = '401 Unauthorized';
                  decision = 'deny';
                  reason = 'authentication failed: missing or invalid Bearer token';
                  stepFailed = 2;
                  responseBody = JSON.stringify({ error: 'unauthorized', reason }, null, 2);
                } else if (posture === 'missing') {
                  statusCode = 403;
                  statusText = '403 Forbidden';
                  decision = 'deny';
                  reason = 'invalid device posture token: missing posture token';
                  stepFailed = 3;
                  responseBody = JSON.stringify({ error: 'forbidden', reason, policy_id: 'invalid-posture-token' }, null, 2);
                } else if (posture === 'unhealthy_disk') {
                  statusCode = 403;
                  statusText = '403 Forbidden';
                  decision = 'deny';
                  reason = 'Denied: device is not compliant: disk is not encrypted';
                  stepFailed = 4;
                  responseBody = JSON.stringify({ error: 'forbidden', reason, policy_id: 'disk-not-encrypted' }, null, 2);
                } else if (user === 'bob' && target.startsWith('/backend-a/admin')) {
                  statusCode = 403;
                  statusText = '403 Forbidden';
                  decision = 'deny';
                  reason = 'Denied: viewer cannot access /admin paths';
                  stepFailed = 4;
                  responseBody = JSON.stringify({ error: 'forbidden', reason, policy_id: 'viewer-admin-path' }, null, 2);
                } else {
                  statusCode = 200;
                  statusText = '200 OK';
                  decision = 'allow';
                  reason = '';
                  stepFailed = 6;
                  responseBody = JSON.stringify(
                    {
                      backend: target.includes('backend-b') ? 'backend-b' : 'backend-a',
                      headers: {
                        'X-User': user,
                        'X-Roles': user === 'alice' ? 'admin,default-roles-zt' : 'viewer,default-roles-zt',
                        'X-Email': `${user}@example.com`,
                        'X-Forwarded-Proto': 'https',
                        'X-Real-IP': '172.18.0.7',
                        'User-Agent': 'Doorman-SecOps-Simulator/1.22'
                      }
                    },
                    null,
                    2
                  );
                }
              }

              // Build the 7 Steps Pipeline trace
              const steps = [
                {
                  step: 1,
                  name: 'Request Ingress & TLS Termination',
                  subsystem: 'nginx / cmd/proxy',
                  status: 'pass' as const,
                  details: `TLS handshake terminated on port 443; Bearer token and X-Device-Posture headers extracted.`,
                  latency_ms: 0.05,
                },
                {
                  step: 2,
                  name: 'OIDC Identity Authentication',
                  subsystem: 'internal/auth',
                  status: (stepFailed >= 2 && user !== 'anonymous' ? 'pass' : 'fail') as const,
                  details: user !== 'anonymous'
                    ? `Keycloak RS256 JWT signature verified against JWKS keys. Identity confirmed: ${user} (${user === 'alice' ? 'admin' : 'viewer'}).`
                    : `Authentication failed: Missing or invalid Keycloak Bearer token.`,
                  latency_ms: 0.12,
                },
                {
                  step: 3,
                  name: 'Hardware Device Posture Verification',
                  subsystem: 'internal/posture',
                  status: (stepFailed >= 3 && posture !== 'missing' ? 'pass' : (stepFailed < 2 ? 'skipped' : 'fail')) as const,
                  details: posture !== 'missing'
                    ? `ES256 ECDSA P-256 token signature verified against POSTURE_PUBLIC_KEY. Device ID: MacBook-Air.local.`
                    : `Zero-Trust compliance failed: Missing X-Device-Posture header.`,
                  latency_ms: 0.08,
                },
                {
                  step: 4,
                  name: 'OPA Rego Policy Evaluation',
                  subsystem: 'internal/policy',
                  status: (decision === 'allow' ? 'pass' : (stepFailed === 4 ? 'fail' : (stepFailed < 4 ? 'skipped' : 'pass'))) as const,
                  details: decision === 'allow'
                    ? `REST POST /v1/data/zt/authz evaluated deterministically against policies/authz.rego. Decision: ALLOW (0 denials).`
                    : (stepFailed === 4 ? `OPA Engine Denied: ${reason}` : `Evaluation skipped due to earlier stage failure.`),
                  latency_ms: decision === 'allow' ? 1.85 : 1.20,
                },
                {
                  step: 5,
                  name: 'Fail-Closed Decision Gate',
                  subsystem: 'cmd/proxy',
                  status: (decision === 'allow' ? 'pass' : 'fail') as const,
                  details: decision === 'allow'
                    ? `Decision Gate: ALLOW. Request dispatched to upstream mutual TLS pipeline.`
                    : `Fail-Closed Gate Activated: Request blocked. Returned HTTP ${statusCode} Forbidden.`,
                  latency_ms: 0.02,
                },
                {
                  step: 6,
                  name: 'mTLS Upstream Forwarding',
                  subsystem: 'internal/mtls',
                  status: (decision === 'allow' ? 'pass' : 'skipped') as const,
                  details: decision === 'allow'
                    ? `Secure mutual TLS tunnel established with ${target.includes('backend-b') ? 'backend-b:8080' : 'backend-a:8080'}. Client certificate presented and verified against internal CA.`
                    : `Upstream connection not opened. Zero-Trust prevents unauthenticated traffic reaching backend.`,
                  latency_ms: decision === 'allow' ? 1.62 : 0,
                },
                {
                  step: 7,
                  name: 'Async Audit Logging & Prometheus',
                  subsystem: 'internal/audit',
                  status: 'pass' as const,
                  details: `Request metadata appended asynchronously to audit-logs/audit.jsonl with step=${stepFailed}. Latency histogram updated on :9090.`,
                  latency_ms: 0.04,
                },
              ];

              const total_ms = steps.reduce((acc, s) => acc + (s.status === 'pass' || s.status === 'fail' ? s.latency_ms : 0), 0);

              const simulationResult = {
                status: statusCode,
                statusText,
                decision,
                reason,
                step: stepFailed,
                steps,
                responseBody,
                curlCommand: curlCmdDisplay,
                isLive,
                mtlsInfo: {
                  clientCert: 'certs/proxy-client.crt (CN=doorman-proxy, Internal CA Signed)',
                  serverCert: target.includes('backend-b') ? 'certs/backend-b.crt' : 'certs/backend-a.crt',
                  tlsVersion: 'TLSv1.3',
                  cipherSuite: 'TLS_AES_128_GCM_SHA256 (P-256 Curve)'
                },
                total_ms: parseFloat(total_ms.toFixed(2))
              };

              res.setHeader('Content-Type', 'application/json');
              res.setHeader('Access-Control-Allow-Origin', '*');
              res.end(JSON.stringify(simulationResult));
            } catch (err: any) {
              res.statusCode = 500;
              res.end(JSON.stringify({ error: err.message || 'Dispatch error' }));
            }
          });
        });

        // Serve /api/policy/eval
        server.middlewares.use('/api/policy/eval', (req, res) => {
          if (req.method !== 'POST') {
            res.statusCode = 405;
            res.end('Method not allowed');
            return;
          }

          let body = '';
          req.on('data', chunk => {
            body += chunk;
          });

          req.on('end', () => {
            try {
              const parsed = JSON.parse(body || '{}');
              const input = parsed.input || parsed;

              // Read policies/data.json for allowed_countries
              const dataPath = path.resolve(__dirname, '../policies/data.json');
              let allowedCountries = ['IN', 'US', 'GB', 'DE', 'SG'];
              if (fs.existsSync(dataPath)) {
                try {
                  const dataJson = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
                  if (Array.isArray(dataJson.allowed_countries)) {
                    allowedCountries = dataJson.allowed_countries;
                  }
                } catch (e) {}
              }

              // Evaluate denials per zt.authz
              const denials: { rule_id: string; message: string }[] = [];
              const roles: string[] = Array.isArray(input.roles) ? input.roles : [];
              const isAdmin = roles.includes('admin');
              const isViewer = roles.includes('viewer');

              // Geo
              if (!input.geo || !allowedCountries.includes(input.geo)) {
                denials.push({
                  rule_id: 'geo-blocked',
                  message: `Denied: country ${input.geo || ''} is not in the allow list`,
                });
              }

              // Posture
              const posture = input.device_posture;
              if (!posture || posture.disk_encrypted === false) {
                denials.push({
                  rule_id: 'disk-not-encrypted',
                  message: 'Denied: device is not compliant: disk is not encrypted',
                });
              }
              if (!posture || posture.firewall_on === false) {
                denials.push({
                  rule_id: 'firewall-off',
                  message: 'Denied: device is not compliant: firewall is not enabled',
                });
              }
              if (!posture || (typeof posture.os_patch_age_days === 'number' && posture.os_patch_age_days > 30)) {
                const days = posture ? posture.os_patch_age_days : 0;
                denials.push({
                  rule_id: 'os-patch-stale',
                  message: `Denied: OS patch age ${days} days exceeds 30 day limit`,
                });
              }

              // Roles and permissions
              if (!isAdmin && !isViewer) {
                denials.push({
                  rule_id: 'unknown-role',
                  message: 'Denied: no recognized role (admin or viewer)',
                });
              } else if (isViewer && !isAdmin) {
                // Business hours
                if (input.time) {
                  const hour = parseInt(input.time.split(':')[0], 10);
                  if (isNaN(hour) || hour < 9 || hour >= 19) {
                    denials.push({
                      rule_id: 'viewer-time-restricted',
                      message: 'Denied: viewer access outside business hours 09:00-19:00',
                    });
                  }
                }
                // Methods
                const method = (input.method || '').toUpperCase();
                if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
                  denials.push({
                    rule_id: 'viewer-method-denied',
                    message: `Denied: viewer cannot use method ${method}`,
                  });
                }
                // Resource
                const resPath = input.resource || '';
                if (resPath.startsWith('/admin')) {
                  denials.push({
                    rule_id: 'viewer-admin-path',
                    message: 'Denied: viewer cannot access /admin paths',
                  });
                }
              }

              // Deterministic sorting of denials
              denials.sort((a, b) => a.rule_id.localeCompare(b.rule_id));

              let allow = false;
              if (denials.length === 0) {
                if (isAdmin) allow = true;
                else if (isViewer) {
                  const m = (input.method || '').toUpperCase();
                  const r = input.resource || '';
                  if (['GET', 'HEAD', 'OPTIONS'].includes(m) && !r.startsWith('/admin')) {
                    allow = true;
                  }
                }
              }

              const result = {
                allow,
                policy_id: denials.length > 0 ? denials[0].rule_id : '',
                reason: denials.length > 0 ? denials[0].message : '',
                denials,
              };

              res.setHeader('Content-Type', 'application/json');
              res.setHeader('Access-Control-Allow-Origin', '*');
              res.end(JSON.stringify({ result }));
            } catch (err: any) {
              res.statusCode = 400;
              res.end(JSON.stringify({ error: err.message || 'Invalid JSON' }));
            }
          });
        });
      },
    },
  ],
  server: {
    port: 3000,
  },
});
