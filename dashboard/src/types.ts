export interface AuditEntry {
  timestamp: string;
  request_id: string;
  user: string;
  roles: string[] | null;
  resource: string;
  method: string;
  decision: 'allow' | 'deny' | string;
  reason: string;
  policy_id: string;
  client_ip: string;
  geo: string;
  device_id: string;
  step: number;
  auth_ms: number;
  opa_ms: number;
  upstream_ms: number;
}

export interface DevicePosture {
  device_id?: string;
  disk_encrypted: boolean;
  firewall_on: boolean;
  os_patch_age_days: number;
}

export interface PolicyInput {
  user: string;
  roles: string[];
  resource: string;
  method: string;
  ip: string;
  geo: string;
  time: string;
  device_posture: DevicePosture;
}

export interface PolicyDenial {
  rule_id: string;
  message: string;
}

export interface PolicyEvaluationResult {
  allow: boolean;
  policy_id: string;
  reason: string;
  denials?: PolicyDenial[];
}

export interface BenchmarkRow {
  timestamp: string;
  scenario: string;
  vus: number;
  rps: number;
  p50_ms: number;
  p90_ms: number;
  p95_ms: number;
  p99_ms: number;
  auth_p95_ms: number;
  opa_p95_ms: number;
  upstream_p95_ms: number;
  error_rate: number;
  cache_enabled: boolean;
}

export interface SimulationStep {
  step: number;
  name: string;
  subsystem: string;
  status: 'pass' | 'fail' | 'pending' | 'skipped';
  details: string;
  latency_ms: number;
}

export interface SimulationResult {
  status: number;
  statusText: string;
  decision: 'allow' | 'deny';
  reason: string;
  step: number;
  steps: SimulationStep[];
  responseBody: string;
  curlCommand: string;
  mtlsInfo: {
    clientCert: string;
    serverCert: string;
    tlsVersion: string;
    cipherSuite: string;
  };
  total_ms: number;
}

export type PageId = 'overview' | 'simulator' | 'audit' | 'policy-tester' | 'benchmarks' | 'about';
