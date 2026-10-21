import { AuditEntry, PolicyInput, PolicyEvaluationResult, BenchmarkRow, SimulationResult } from './types';

// Fallback audit entries if server has no log file
export const SAMPLE_AUDIT_ENTRIES: AuditEntry[] = [
  {
    timestamp: "2026-10-21T18:00:10.109Z",
    request_id: "1792605610104152428",
    user: "alice",
    roles: ["admin", "default-roles-zt"],
    resource: "/backend-a/data",
    method: "GET",
    decision: "allow",
    reason: "",
    policy_id: "",
    client_ip: "172.18.0.7",
    geo: "IN",
    device_id: "sec-ops-mac-01",
    step: 6,
    auth_ms: 0.202,
    opa_ms: 3.122,
    upstream_ms: 1.939
  },
  {
    timestamp: "2026-10-21T18:00:10.120Z",
    request_id: "1792605610118869178",
    user: "bob",
    roles: ["viewer", "default-roles-zt"],
    resource: "/admin",
    method: "GET",
    decision: "deny",
    reason: "Denied: viewer cannot access /admin paths",
    policy_id: "viewer-admin-path",
    client_ip: "172.18.0.7",
    geo: "IN",
    device_id: "sec-ops-mac-01",
    step: 4,
    auth_ms: 0.090,
    opa_ms: 1.243,
    upstream_ms: 0
  },
  {
    timestamp: "2026-10-21T18:00:10.132Z",
    request_id: "1792605610130093845",
    user: "alice",
    roles: ["admin", "default-roles-zt"],
    resource: "/backend-b/reports",
    method: "GET",
    decision: "deny",
    reason: "Denied: device is not compliant: disk is not encrypted",
    policy_id: "disk-not-encrypted",
    client_ip: "172.18.0.7",
    geo: "IN",
    device_id: "sec-ops-mac-01",
    step: 4,
    auth_ms: 0.133,
    opa_ms: 1.491,
    upstream_ms: 0
  },
  {
    timestamp: "2026-10-21T18:00:10.140Z",
    request_id: "1792605610140486428",
    user: "",
    roles: null,
    resource: "/backend-a/data",
    method: "GET",
    decision: "deny",
    reason: "authentication failed",
    policy_id: "authentication",
    client_ip: "172.18.0.7",
    geo: "",
    device_id: "",
    step: 1,
    auth_ms: 0.038,
    opa_ms: 0,
    upstream_ms: 0
  },
  {
    timestamp: "2026-10-21T18:00:11.208Z",
    request_id: "1792605611208155846",
    user: "alice",
    roles: ["admin"],
    resource: "/api/audit",
    method: "GET",
    decision: "allow",
    reason: "",
    policy_id: "",
    client_ip: "172.18.0.7",
    geo: "IN",
    device_id: "sec-ops-mac-01",
    step: 6,
    auth_ms: 0.095,
    opa_ms: 0.812,
    upstream_ms: 0.420
  }
];

export async function fetchAuditEntries(filters?: {
  user?: string;
  decision?: string;
  resource?: string;
}): Promise<{ entries: AuditEntry[]; isSample: boolean }> {
  const params = new URLSearchParams();
  if (filters?.user) params.set('user', filters.user);
  if (filters?.decision) params.set('decision', filters.decision);
  if (filters?.resource) params.set('resource', filters.resource);

  const query = params.toString() ? `?${params.toString()}` : '';

  try {
    const res = await fetch(`/api/audit${query}`);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    const data = await res.json();
    if (Array.isArray(data) && data.length > 0) {
      return { entries: data, isSample: false };
    }
  } catch (err) {
    console.warn('Failed to fetch from /api/audit, using sample audit records:', err);
  }

  // Filter fallback sample data if backend endpoint is unavailable or empty
  let filtered = [...SAMPLE_AUDIT_ENTRIES];
  if (filters?.user) {
    filtered = filtered.filter(e => e.user.toLowerCase().includes(filters.user!.toLowerCase()));
  }
  if (filters?.decision) {
    filtered = filtered.filter(e => e.decision.toLowerCase() === filters.decision!.toLowerCase());
  }
  if (filters?.resource) {
    filtered = filtered.filter(e => e.resource.toLowerCase().includes(filters.resource!.toLowerCase()));
  }
  return { entries: filtered, isSample: true };
}

// Client-side OPA evaluator matching policies/authz.rego
export function evaluatePolicyLocally(input: PolicyInput): PolicyEvaluationResult {
  const allowedCountries = ['IN', 'US', 'GB', 'DE', 'SG'];
  const denials: { rule_id: string; message: string }[] = [];
  const roles = Array.isArray(input.roles) ? input.roles : [];
  const isAdmin = roles.includes('admin');
  const isViewer = roles.includes('viewer');

  // Geo-blocking: country must be in the allow list
  if (!input.geo || !allowedCountries.includes(input.geo)) {
    denials.push({
      rule_id: 'geo-blocked',
      message: `Denied: country ${input.geo || ''} is not in the allow list`,
    });
  }

  // Device posture: disk must be encrypted
  if (!input.device_posture || input.device_posture.disk_encrypted === false) {
    denials.push({
      rule_id: 'disk-not-encrypted',
      message: 'Denied: device is not compliant: disk is not encrypted',
    });
  }

  // Device posture: firewall must be enabled
  if (!input.device_posture || input.device_posture.firewall_on === false) {
    denials.push({
      rule_id: 'firewall-off',
      message: 'Denied: device is not compliant: firewall is not enabled',
    });
  }

  // Device posture: OS patch age must be <= 30 days
  if (!input.device_posture || input.device_posture.os_patch_age_days > 30) {
    const days = input.device_posture ? input.device_posture.os_patch_age_days : 0;
    denials.push({
      rule_id: 'os-patch-stale',
      message: `Denied: OS patch age ${days} days exceeds 30 day limit`,
    });
  }

  // Role validation
  if (!isAdmin && !isViewer) {
    denials.push({
      rule_id: 'unknown-role',
      message: 'Denied: no recognized role (admin or viewer)',
    });
  } else if (isViewer && !isAdmin) {
    // Viewer: denied outside business hours (09:00-19:00)
    if (input.time) {
      const hour = parseInt(input.time.split(':')[0], 10);
      if (isNaN(hour) || hour < 9 || hour >= 19) {
        denials.push({
          rule_id: 'viewer-time-restricted',
          message: 'Denied: viewer access outside business hours 09:00-19:00',
        });
      }
    }
    // Viewer: read-only methods only
    const method = (input.method || '').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      denials.push({
        rule_id: 'viewer-method-denied',
        message: `Denied: viewer cannot use method ${method}`,
      });
    }
    // Viewer: denied access to /admin paths
    const resource = input.resource || '';
    if (resource.startsWith('/admin')) {
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

  return {
    allow,
    policy_id: denials.length > 0 ? denials[0].rule_id : '',
    reason: denials.length > 0 ? denials[0].message : '',
    denials,
  };
}

export async function evaluatePolicy(input: PolicyInput): Promise<PolicyEvaluationResult> {
  try {
    const res = await fetch('/api/policy/eval', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.result) {
        return data.result;
      }
    }
  } catch (err) {
    // fallback to local evaluation
  }
  return evaluatePolicyLocally(input);
}

// Parse CSV format from bench/results.csv
export async function fetchBenchmarks(): Promise<{ rows: BenchmarkRow[]; isSample: boolean }> {
  try {
    const res = await fetch('/bench/results.csv');
    if (res.ok) {
      const text = await res.text();
      const lines = text.trim().split('\n');
      if (lines.length > 1) {
        const rows: BenchmarkRow[] = [];
        for (let i = 1; i < lines.length; i++) {
          const cols = lines[i].split(',').map(s => s.trim());
          if (cols.length >= 13) {
            rows.push({
              timestamp: cols[0],
              scenario: cols[1],
              vus: parseInt(cols[2], 10),
              rps: parseFloat(cols[3]),
              p50_ms: parseFloat(cols[4]),
              p90_ms: parseFloat(cols[5]),
              p95_ms: parseFloat(cols[6]),
              p99_ms: parseFloat(cols[7]),
              auth_p95_ms: parseFloat(cols[8]),
              opa_p95_ms: parseFloat(cols[9]),
              upstream_p95_ms: parseFloat(cols[10]),
              error_rate: parseFloat(cols[11]),
              cache_enabled: cols[12] === 'true',
            });
          }
        }
        if (rows.length > 0) {
          return { rows, isSample: true };
        }
      }
    }
  } catch (err) {
    console.warn('Failed to load /bench/results.csv:', err);
  }

  return {
    rows: [
      {
        timestamp: "2026-10-21T14:00:00Z",
        scenario: "cache_hit_10vu",
        vus: 10,
        rps: 1250.4,
        p50_ms: 2.15,
        p90_ms: 4.82,
        p95_ms: 7.34,
        p99_ms: 11.20,
        auth_p95_ms: 0.18,
        opa_p95_ms: 0.42,
        upstream_p95_ms: 4.80,
        error_rate: 0.00,
        cache_enabled: true
      },
      {
        timestamp: "2026-10-21T14:10:00Z",
        scenario: "cache_hit_25vu",
        vus: 25,
        rps: 2840.1,
        p50_ms: 2.80,
        p90_ms: 6.10,
        p95_ms: 8.95,
        p99_ms: 14.50,
        auth_p95_ms: 0.22,
        opa_p95_ms: 0.55,
        upstream_p95_ms: 6.20,
        error_rate: 0.00,
        cache_enabled: true
      },
      {
        timestamp: "2026-10-21T14:20:00Z",
        scenario: "cache_hit_50vu",
        vus: 50,
        rps: 4910.8,
        p50_ms: 3.40,
        p90_ms: 7.60,
        p95_ms: 10.80,
        p99_ms: 18.20,
        auth_p95_ms: 0.29,
        opa_p95_ms: 0.78,
        upstream_p95_ms: 7.90,
        error_rate: 0.01,
        cache_enabled: true
      },
      {
        timestamp: "2026-10-21T14:30:00Z",
        scenario: "cache_hit_100vu",
        vus: 100,
        rps: 7820.5,
        p50_ms: 4.10,
        p90_ms: 8.90,
        p95_ms: 11.85,
        p99_ms: 22.40,
        auth_p95_ms: 0.38,
        opa_p95_ms: 0.95,
        upstream_p95_ms: 8.80,
        error_rate: 0.02,
        cache_enabled: true
      },
      {
        timestamp: "2026-10-21T14:40:00Z",
        scenario: "cache_miss_10vu",
        vus: 10,
        rps: 890.2,
        p50_ms: 4.60,
        p90_ms: 9.40,
        p95_ms: 13.80,
        p99_ms: 19.50,
        auth_p95_ms: 0.21,
        opa_p95_ms: 4.10,
        upstream_p95_ms: 5.10,
        error_rate: 0.00,
        cache_enabled: false
      },
      {
        timestamp: "2026-10-21T14:50:00Z",
        scenario: "cache_miss_25vu",
        vus: 25,
        rps: 1820.0,
        p50_ms: 5.80,
        p90_ms: 12.20,
        p95_ms: 16.90,
        p99_ms: 26.10,
        auth_p95_ms: 0.26,
        opa_p95_ms: 5.30,
        upstream_p95_ms: 7.20,
        error_rate: 0.00,
        cache_enabled: false
      },
      {
        timestamp: "2026-10-21T15:00:00Z",
        scenario: "cache_miss_50vu",
        vus: 50,
        rps: 2950.4,
        p50_ms: 7.40,
        p90_ms: 15.80,
        p95_ms: 21.50,
        p99_ms: 34.80,
        auth_p95_ms: 0.34,
        opa_p95_ms: 7.80,
        upstream_p95_ms: 9.40,
        error_rate: 0.02,
        cache_enabled: false
      },
      {
        timestamp: "2026-10-21T15:10:00Z",
        scenario: "cache_miss_100vu",
        vus: 100,
        rps: 4100.2,
        p50_ms: 9.90,
        p90_ms: 21.40,
        p95_ms: 29.10,
        p99_ms: 48.20,
        auth_p95_ms: 0.45,
        opa_p95_ms: 11.20,
        upstream_p95_ms: 12.80,
        error_rate: 0.05,
        cache_enabled: false
      }
    ],
    isSample: true,
  };
}

export function formatLocalTimestamp(ts?: string): string {
  if (!ts) return '-';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) {
      return ts.replace('T', ' ').substring(0, 19);
    }
    const pad = (n: number) => String(n).padStart(2, '0');
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hh = pad(d.getHours());
    const min = pad(d.getMinutes());
    const ss = pad(d.getSeconds());
    return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
  } catch {
    return ts.replace('T', ' ').substring(0, 19);
  }
}

export async function dispatchLiveRequest(params: {
  user: string;
  posture: string;
  target: string;
  method: string;
}): Promise<SimulationResult> {
  try {
    const res = await fetch('/api/dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {}

  // Fallback if standalone without Vite middleware
  const isAnon = params.user === 'anonymous';
  const isMissingPosture = params.posture === 'missing';
  const isBadPosture = params.posture === 'unhealthy_disk' || params.posture === 'unhealthy_firewall';
  const isBobAdmin = params.user === 'bob' && params.target.startsWith('/backend-a/admin');

  let statusCode = 200;
  let statusText = '200 OK';
  let decision: 'allow' | 'deny' = 'allow';
  let reason = '';
  let step = 6;

  if (isAnon) {
    statusCode = 401;
    statusText = '401 Unauthorized';
    decision = 'deny';
    reason = 'authentication failed: missing Bearer token';
    step = 2;
  } else if (isMissingPosture) {
    statusCode = 403;
    statusText = '403 Forbidden';
    decision = 'deny';
    reason = 'invalid device posture token: missing posture token';
    step = 3;
  } else if (isBadPosture) {
    statusCode = 403;
    statusText = '403 Forbidden';
    decision = 'deny';
    reason = 'Denied: device is not compliant: disk is not encrypted';
    step = 4;
  } else if (isBobAdmin) {
    statusCode = 403;
    statusText = '403 Forbidden';
    decision = 'deny';
    reason = 'Denied: viewer cannot access /admin paths';
    step = 4;
  }

  return {
    status: statusCode,
    statusText,
    decision,
    reason,
    step,
    steps: [
      { step: 1, name: 'Request Ingress', subsystem: 'nginx / cmd/proxy', status: 'pass', details: 'TLS terminated on port 443', latency_ms: 0.05 },
      { step: 2, name: 'OIDC Authentication', subsystem: 'internal/auth', status: isAnon ? 'fail' : 'pass', details: isAnon ? 'Missing token' : `Identity verified: ${params.user}`, latency_ms: 0.12 },
      { step: 3, name: 'Device Posture', subsystem: 'internal/posture', status: isMissingPosture ? 'fail' : (isAnon ? 'skipped' : 'pass'), details: isMissingPosture ? 'Missing posture header' : 'ES256 signature verified', latency_ms: 0.08 },
      { step: 4, name: 'OPA Policy Evaluation', subsystem: 'internal/policy', status: (isBadPosture || isBobAdmin) ? 'fail' : ((isAnon || isMissingPosture) ? 'skipped' : 'pass'), details: reason || '0 denials', latency_ms: 1.45 },
      { step: 5, name: 'Decision Gate', subsystem: 'cmd/proxy', status: decision === 'allow' ? 'pass' : 'fail', details: decision === 'allow' ? 'Allowed' : 'Blocked', latency_ms: 0.02 },
      { step: 6, name: 'mTLS Upstream Forwarding', subsystem: 'internal/mtls', status: decision === 'allow' ? 'pass' : 'skipped', details: decision === 'allow' ? 'mTLS established' : 'Skipped', latency_ms: 1.62 },
      { step: 7, name: 'Async Audit Log', subsystem: 'internal/audit', status: 'pass', details: 'Audit record appended', latency_ms: 0.04 },
    ],
    responseBody: decision === 'allow' ? JSON.stringify({ backend: 'backend-a', headers: { 'X-User': params.user } }, null, 2) : JSON.stringify({ error: 'forbidden', reason }, null, 2),
    curlCommand: `curl -k -i https://localhost${params.target}`,
    mtlsInfo: {
      clientCert: 'certs/proxy-client.crt (CN=doorman-proxy, Internal CA Signed)',
      serverCert: 'certs/backend-a.crt (CN=backend-a, Internal CA Signed)',
      tlsVersion: 'TLSv1.3',
      cipherSuite: 'TLS_AES_128_GCM_SHA256'
    },
    total_ms: 2.15,
  };
}
