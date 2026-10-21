import React from 'react';

export const AboutPage: React.FC = () => {
  const steps = [
    {
      step: 1,
      name: 'REQUEST_INGRESS',
      subsystem: 'nginx / proxy',
      description: 'Incoming HTTPS request terminated; Bearer token and X-Device-Posture headers extracted.',
    },
    {
      step: 2,
      name: 'OIDC_VALIDATION',
      subsystem: 'internal/auth',
      description: 'Keycloak JWT signature validated against realm public keys; username and roles extracted.',
    },
    {
      step: 3,
      name: 'POSTURE_GEO_CHECK',
      subsystem: 'internal/posture',
      description: 'ES256 posture token signature verified against POSTURE_PUBLIC_KEY; claims and client geo verified.',
    },
    {
      step: 4,
      name: 'OPA_POLICY_EVAL',
      subsystem: 'internal/policy',
      description: 'Input sent to OPA (POST /v1/data/zt/authz); in-memory cache checked; denials evaluated deterministically.',
    },
    {
      step: 5,
      name: 'DECISION_DISPATCH',
      subsystem: 'cmd/proxy',
      description: 'Fail-closed decision gate; if allow is false, HTTP 403 Forbidden is returned with specific reason.',
    },
    {
      step: 6,
      name: 'MTLS_UPSTREAM',
      subsystem: 'internal/mtls',
      description: 'mTLS HTTP transport connects to backend presenting client cert and verifying backend against internal CA.',
    },
    {
      step: 7,
      name: 'ASYNC_AUDIT_LOG',
      subsystem: 'internal/audit',
      description: 'Entry queued to asynchronous worker, appended to audit.jsonl, and recorded in Prometheus latency histograms.',
    },
  ];

  const denialRules = [
    { rule_id: 'geo-blocked', trigger: 'Country not in policies/data.json allowed list', sample: 'Denied: country XX is not in the allow list' },
    { rule_id: 'disk-not-encrypted', trigger: 'device_posture.disk_encrypted == false', sample: 'Denied: device is not compliant: disk is not encrypted' },
    { rule_id: 'firewall-off', trigger: 'device_posture.firewall_on == false', sample: 'Denied: device is not compliant: firewall is not enabled' },
    { rule_id: 'os-patch-stale', trigger: 'device_posture.os_patch_age_days > 30', sample: 'Denied: OS patch age 45 days exceeds 30 day limit' },
    { rule_id: 'viewer-time-restricted', trigger: 'Viewer access outside 09:00 to 19:00', sample: 'Denied: viewer access outside business hours 09:00-19:00' },
    { rule_id: 'viewer-method-denied', trigger: 'Viewer access with non-read method', sample: 'Denied: viewer cannot use method POST' },
    { rule_id: 'viewer-admin-path', trigger: 'Viewer access to /admin path', sample: 'Denied: viewer cannot access /admin paths' },
    { rule_id: 'unknown-role', trigger: 'User lacks admin or viewer role', sample: 'Denied: no recognized role (admin or viewer)' },
  ];

  const envVars = [
    { name: 'PROXY_LISTEN_ADDR', default: ':8080', desc: 'Bind address for proxy ingress HTTP/HTTPS' },
    { name: 'OIDC_ISSUER_URL', default: 'http://keycloak:8080/realms/zt', desc: 'OpenID Connect provider realm endpoint' },
    { name: 'OPA_URL', default: 'http://opa:8181', desc: 'Open Policy Agent REST service URL' },
    { name: 'POSTURE_PUBLIC_KEY', default: '(required)', desc: 'Hex-encoded ECDSA P-256 public key for posture token verification' },
    { name: 'MTLS_CA_FILE', default: '/certs/ca.crt', desc: 'Internal Certificate Authority for mTLS upstream verification' },
    { name: 'MTLS_CLIENT_CERT_FILE', default: '/certs/proxy-client.crt', desc: 'Proxy client certificate for upstream authentication' },
    { name: 'AUDIT_LOG_FILE', default: '/var/log/doorman/audit.jsonl', desc: 'JSON lines audit log destination file' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
          About Doorman Ingress Proxy
        </h1>
        <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
          Zero-Trust identity-aware architecture, verification pipeline stages, and policy specification
        </p>
      </div>

      {/* Architecture Overview */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-3">
        <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide border-b border-neutral-200 dark:border-neutral-800 pb-2">
          Architecture Specification
        </h2>
        <p className="text-xs text-neutral-800 dark:text-neutral-200 leading-relaxed font-sans">
          Doorman is a Zero-Trust identity-aware ingress proxy implemented in Go 1.22. Every incoming request is subjected to
          mandatory authentication via OpenID Connect (Keycloak), hardware and OS posture verification via ECDSA ES256 tokens,
          and authorization through Open Policy Agent (OPA) with Rego policies over REST. Forwarding to backend microservices
          is secured using mutual TLS (mTLS) with hot-reloading 24-hour certificates.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs font-mono">
          <div className="p-2 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950">
            <span className="text-neutral-500 block text-[10px]">CORE RUNTIME</span>
            <span className="font-semibold text-neutral-900 dark:text-neutral-100">Go 1.22 Standard Library</span>
          </div>
          <div className="p-2 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950">
            <span className="text-neutral-500 block text-[10px]">TARGET ADDED LATENCY</span>
            <span className="font-semibold text-neutral-900 dark:text-neutral-100">p95 &lt; 12 ms (cache enabled)</span>
          </div>
          <div className="p-2 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950">
            <span className="text-neutral-500 block text-[10px]">ERROR POLICY</span>
            <span className="font-semibold text-neutral-900 dark:text-neutral-100">Fail-closed on any fault</span>
          </div>
        </div>
      </div>

      {/* Step Numbers & Verification Flow Table */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            Request Verification Pipeline (Steps 1 through 7)
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">MANDATORY FLOW</span>
        </div>

        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 text-neutral-600 dark:text-neutral-400">
                <th className="py-2 px-3 font-medium w-16">STEP</th>
                <th className="py-2 px-3 font-medium w-48">STAGE NAME</th>
                <th className="py-2 px-3 font-medium w-40">MODULE</th>
                <th className="py-2 px-3 font-medium">DESCRIPTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
              {steps.map((s) => (
                <tr key={s.step} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                  <td className="py-2 px-3 font-bold text-accent">STEP {s.step}</td>
                  <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">{s.name}</td>
                  <td className="py-2 px-3 text-neutral-600 dark:text-neutral-400">{s.subsystem}</td>
                  <td className="py-2 px-3 text-neutral-800 dark:text-neutral-200">{s.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Policy Denial Catalog */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            OPA Policy Rule Catalog (policies/authz.rego)
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">8 FORMAL RULES</span>
        </div>

        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 text-neutral-600 dark:text-neutral-400">
                <th className="py-2 px-3 font-medium w-48">RULE ID</th>
                <th className="py-2 px-3 font-medium">TRIGGER CONDITION</th>
                <th className="py-2 px-3 font-medium">SPECIFIC DENIAL MESSAGE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
              {denialRules.map((r) => (
                <tr key={r.rule_id} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                  <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">{r.rule_id}</td>
                  <td className="py-2 px-3 text-neutral-700 dark:text-neutral-300">{r.trigger}</td>
                  <td className="py-2 px-3 text-status-deny dark:text-status-deny-dark">{r.sample}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Configuration Variables */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            Key Configuration Variables
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">ENV VAR CONFIG</span>
        </div>

        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 text-neutral-600 dark:text-neutral-400">
                <th className="py-2 px-3 font-medium w-56">VARIABLE</th>
                <th className="py-2 px-3 font-medium w-64">DEFAULT VALUE</th>
                <th className="py-2 px-3 font-medium">PURPOSE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
              {envVars.map((v) => (
                <tr key={v.name} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                  <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">{v.name}</td>
                  <td className="py-2 px-3 text-neutral-600 dark:text-neutral-400 text-[11px]">{v.default}</td>
                  <td className="py-2 px-3 text-neutral-800 dark:text-neutral-200">{v.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
