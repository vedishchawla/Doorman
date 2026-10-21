import React, { useState } from 'react';
import { SimulationResult } from '../types';
import { dispatchLiveRequest } from '../api';

interface Preset {
  id: string;
  label: string;
  badge: 'ALLOW' | 'DENY';
  user: string;
  posture: string;
  target: string;
  method: string;
  description: string;
}

const PRESETS: Preset[] = [
  {
    id: 'alice-backend-a',
    label: 'Alice (Admin) -> Backend A',
    badge: 'ALLOW',
    user: 'alice',
    posture: 'compliant',
    target: '/backend-a/',
    method: 'GET',
    description: 'Fully compliant request: Admin user + Encrypted Mac + Valid OPA rule -> mTLS forwarded to Backend A.',
  },
  {
    id: 'bob-admin-denied',
    label: 'Bob (Viewer) -> /admin Path',
    badge: 'DENY',
    user: 'bob',
    posture: 'compliant',
    target: '/backend-a/admin',
    method: 'GET',
    description: 'Role-based denial: OPA Rego rule blocks viewer from accessing /admin paths (HTTP 403).',
  },
  {
    id: 'alice-unencrypted-disk',
    label: 'Alice -> Unencrypted Disk',
    badge: 'DENY',
    user: 'alice',
    posture: 'unhealthy_disk',
    target: '/backend-a/',
    method: 'GET',
    description: 'Hardware posture denial: ES256 hardware token indicates unencrypted disk -> OPA rejects request.',
  },
  {
    id: 'missing-posture-browser',
    label: 'Browser Access (Missing Posture)',
    badge: 'DENY',
    user: 'alice',
    posture: 'missing',
    target: '/backend-a/',
    method: 'GET',
    description: 'Zero-Trust fail-closed: Standard browsers without X-Device-Posture header are rejected at Step 3.',
  },
  {
    id: 'alice-backend-b',
    label: 'Alice (Admin) -> Backend B',
    badge: 'ALLOW',
    user: 'alice',
    posture: 'compliant',
    target: '/backend-b/',
    method: 'GET',
    description: 'Cross-service routing: Verified mTLS channel to Backend B microservice on port 8080.',
  },
  {
    id: 'unauthenticated-attacker',
    label: 'Anonymous Attacker (No Token)',
    badge: 'DENY',
    user: 'anonymous',
    posture: 'compliant',
    target: '/backend-a/',
    method: 'GET',
    description: 'Missing OIDC bearer token: Ingress pipeline immediately rejects at Step 2 (HTTP 401).',
  },
];

export const SimulatorPage: React.FC = () => {
  const [user, setUser] = useState<string>('alice');
  const [posture, setPosture] = useState<string>('compliant');
  const [target, setTarget] = useState<string>('/backend-a/');
  const [method, setMethod] = useState<string>('GET');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [activeStepTab, setActiveStepTab] = useState<number | null>(null);
  const [deepDiveTab, setDeepDiveTab] = useState<'mtls' | 'opa' | 'oidc' | 'posture' | 'architecture'>('mtls');
  const [copied, setCopied] = useState<boolean>(false);

  const applyPreset = (p: Preset) => {
    setUser(p.user);
    setPosture(p.posture);
    setTarget(p.target);
    setMethod(p.method);
    handleDispatch(p.user, p.posture, p.target, p.method);
  };

  const handleDispatch = async (
    targetUser = user,
    targetPosture = posture,
    targetPath = target,
    targetMethod = method
  ) => {
    setLoading(true);
    try {
      const res = await dispatchLiveRequest({
        user: targetUser,
        posture: targetPosture,
        target: targetPath,
        method: targetMethod,
      });
      setResult(res);
      // default open the failing or final step
      setActiveStepTab(res.decision === 'deny' ? res.step : 6);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const copyCurl = () => {
    if (!result?.curlCommand) return;
    navigator.clipboard.writeText(result.curlCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-3 flex flex-col md:flex-row md:items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
              Live Zero-Trust Pipeline Simulator
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium">
              LIVE BACKEND CONNECTED
            </span>
          </div>
          <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
            Dispatch real requests through Keycloak OIDC, ES256 Posture verification, OPA Rego evaluation, and mTLS forward
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-neutral-500">BACKEND TARGET:</span>
          <span className="px-2 py-0.5 bg-neutral-200 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 font-bold">
            https://localhost (NGINX:443 &rarr; PROXY:8080)
          </span>
        </div>
      </div>

      {/* Preset Scenarios Strip */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            1-Click Demo Scenarios (For Viva / Presentation)
          </span>
          <span className="text-[11px] text-neutral-500 font-mono">Click to test scenario instantly</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {PRESETS.map((p) => {
            const isAllow = p.badge === 'ALLOW';
            return (
              <button
                key={p.id}
                onClick={() => applyPreset(p)}
                disabled={loading}
                className="text-left p-2.5 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 hover:border-neutral-400 dark:hover:border-neutral-600 transition flex flex-col justify-between group"
              >
                <div className="flex items-center justify-between gap-1 w-full mb-1">
                  <span className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition">
                    {p.label}
                  </span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.2 font-bold ${
                      isAllow
                        ? 'border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                        : 'border border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                    }`}
                  >
                    {p.badge}
                  </span>
                </div>
                <p className="text-[11px] text-neutral-500 line-clamp-2 leading-snug">
                  {p.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Request Builder */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-4">
        <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide border-b border-neutral-200 dark:border-neutral-800 pb-2">
          Custom Request Builder
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
          {/* Identity */}
          <div className="space-y-1">
            <label className="text-neutral-500 font-semibold block">1. IDENTITY (OIDC / KEYCLOAK)</label>
            <select
              value={user}
              onChange={(e) => setUser(e.target.value)}
              className="w-full p-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100"
            >
              <option value="alice">Alice (Role: admin, Full Access)</option>
              <option value="bob">Bob (Role: viewer, Read-Only)</option>
              <option value="anonymous">Anonymous (No Token / Attacker)</option>
            </select>
            <span className="text-[10px] text-neutral-500 block">
              Generates RS256 JWT from Keycloak realm `zt`
            </span>
          </div>

          {/* Device Posture */}
          <div className="space-y-1">
            <label className="text-neutral-500 font-semibold block">2. DEVICE POSTURE (HARDWARE)</label>
            <select
              value={posture}
              onChange={(e) => setPosture(e.target.value)}
              className="w-full p-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100"
            >
              <option value="compliant">Compliant (Disk Encrypted, Firewall ON)</option>
              <option value="unhealthy_disk">Unhealthy Disk (Disk Unencrypted)</option>
              <option value="unhealthy_firewall">Unhealthy Firewall (Firewall OFF)</option>
              <option value="missing">Missing Posture (Standard Browser)</option>
            </select>
            <span className="text-[10px] text-neutral-500 block">
              ES256 ECDSA token verified against public key
            </span>
          </div>

          {/* Target Service & Path */}
          <div className="space-y-1">
            <label className="text-neutral-500 font-semibold block">3. TARGET RESOURCE</label>
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full p-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100"
            >
              <option value="/backend-a/">/backend-a/ (Echo Service A)</option>
              <option value="/backend-a/admin">/backend-a/admin (Admin Protected)</option>
              <option value="/backend-b/">/backend-b/ (Echo Service B)</option>
            </select>
            <span className="text-[10px] text-neutral-500 block">
              Forwarded over mTLS channel
            </span>
          </div>

          {/* HTTP Method */}
          <div className="space-y-1">
            <label className="text-neutral-500 font-semibold block">4. HTTP METHOD</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full p-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100"
            >
              <option value="GET">GET (Read request)</option>
              <option value="POST">POST (Write request)</option>
              <option value="DELETE">DELETE (Delete request)</option>
            </select>
            <span className="text-[10px] text-neutral-500 block">
              Viewer role restricted to GET/HEAD
            </span>
          </div>
        </div>

        {/* Action Button */}
        <div className="pt-2 flex items-center justify-between">
          <button
            onClick={() => handleDispatch()}
            disabled={loading}
            className={`px-5 py-2.5 font-mono text-xs font-bold uppercase tracking-wider text-white transition flex items-center gap-2 ${
              loading
                ? 'bg-neutral-500 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600'
            }`}
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>PIPELINE EXECUTING...</span>
              </>
            ) : (
              <>
                <span>▶ EXECUTE REQUEST THROUGH PIPELINE</span>
              </>
            )}
          </button>

          {result && (
            <div className="flex items-center gap-3 font-mono text-xs">
              <span className="text-neutral-500">PIPELINE OUTCOME:</span>
              <span
                className={`px-2.5 py-1 font-bold ${
                  result.decision === 'allow'
                    ? 'border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                    : 'border border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                }`}
              >
                {result.statusText.toUpperCase()} ({result.decision.toUpperCase()})
              </span>
              <span className="text-neutral-500">TOTAL LATENCY: {result.total_ms}ms</span>
            </div>
          )}
        </div>
      </div>

      {/* 7-Step Interactive Pipeline Diagram */}
      {result && (
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
            <div>
              <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
                7-Step Zero-Trust Verification Pipeline (Live Trace)
              </h2>
              <p className="text-[11px] text-neutral-500 font-mono mt-0.5">
                Every request traverses these steps. Fail-closed: any failure halts forwarding immediately.
              </p>
            </div>
            <span className="text-[10px] font-mono text-neutral-500">
              Click any step to inspect Go subsystem & payload
            </span>
          </div>

          {/* Step Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-2">
            {result.steps.map((st) => {
              const isPass = st.status === 'pass';
              const isFail = st.status === 'fail';
              const isSelected = activeStepTab === st.step;

              return (
                <button
                  key={st.step}
                  onClick={() => setActiveStepTab(st.step)}
                  className={`text-left p-2.5 border transition flex flex-col justify-between ${
                    isSelected
                      ? 'border-blue-600 dark:border-blue-400 bg-blue-50/50 dark:bg-blue-950/30'
                      : 'border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 hover:border-neutral-400'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono font-bold text-neutral-500">
                        STEP {st.step}
                      </span>
                      <span
                        className={`text-[9px] font-mono px-1 py-0.2 font-bold ${
                          isPass
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : isFail
                            ? 'text-rose-600 dark:text-rose-400'
                            : 'text-neutral-400'
                        }`}
                      >
                        {isPass ? 'PASS' : isFail ? 'FAIL' : 'SKIPPED'}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 leading-tight">
                      {st.name}
                    </div>
                  </div>

                  <div className="mt-2 pt-2 border-t border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-[10px] font-mono text-neutral-500">
                    <span className="truncate max-w-[80px]">{st.subsystem}</span>
                    <span>{st.latency_ms > 0 ? `${st.latency_ms}ms` : '-'}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Step Details Panel */}
          {activeStepTab && (
            <div className="p-3 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 space-y-2">
              {(() => {
                const stepObj = result.steps.find((s) => s.step === activeStepTab);
                if (!stepObj) return null;
                const isPass = stepObj.status === 'pass';
                const isFail = stepObj.status === 'fail';

                return (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-neutral-900 dark:text-neutral-100">
                          Step {stepObj.step}: {stepObj.name}
                        </span>
                        <span className="text-neutral-400">|</span>
                        <span className="text-neutral-500">Go Package: `{stepObj.subsystem}`</span>
                      </div>
                      <span
                        className={`px-2 py-0.5 text-[10px] font-bold ${
                          isPass
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                            : isFail
                            ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                            : 'bg-neutral-200 dark:bg-neutral-800 text-neutral-500'
                        }`}
                      >
                        STATUS: {stepObj.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-neutral-700 dark:text-neutral-300 font-sans text-xs">
                      {stepObj.details}
                    </p>
                  </div>
                );
              })()}
            </div>
          )}
        </div>
      )}

      {/* Terminal Output & Live Response */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Response Body & Headers */}
          <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
              <span className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
                Live HTTP Response From Backend
              </span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 font-bold ${
                  result.status === 200
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                    : 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                }`}
              >
                STATUS: {result.statusText}
              </span>
            </div>

            <pre className="p-3 bg-neutral-950 text-neutral-200 font-mono text-xs overflow-x-auto max-h-60 leading-relaxed rounded-none border border-neutral-800">
              {result.responseBody || '(empty body)'}
            </pre>

            {/* mTLS Cryptographic Handshake Inspector */}
            <div className="p-3 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between text-neutral-900 dark:text-neutral-100 font-semibold">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
                  Upstream mTLS Verification Details
                </span>
                <span className="text-[10px] text-neutral-500">{result.mtlsInfo.tlsVersion}</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-neutral-600 dark:text-neutral-400">
                <div>
                  <span className="text-neutral-400 block text-[9px]">CLIENT CERTIFICATE</span>
                  <span className="font-semibold text-neutral-800 dark:text-neutral-200">{result.mtlsInfo.clientCert}</span>
                </div>
                <div>
                  <span className="text-neutral-400 block text-[9px]">SERVER CERTIFICATE</span>
                  <span className="font-semibold text-neutral-800 dark:text-neutral-200">{result.mtlsInfo.serverCert}</span>
                </div>
                <div className="sm:col-span-2">
                  <span className="text-neutral-400 block text-[9px]">CIPHER SUITE</span>
                  <span>{result.mtlsInfo.cipherSuite}</span>
                </div>
              </div>
            </div>
          </div>

          {/* cURL Command Equivalent */}
          <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-3 flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
                <span className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
                  Equivalent Terminal CLI Command
                </span>
                <button
                  onClick={copyCurl}
                  className="text-[11px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 hover:bg-neutral-200 text-neutral-700 dark:text-neutral-300 transition"
                >
                  {copied ? '✓ COPIED' : 'COPY CURL'}
                </button>
              </div>
              <p className="text-[11px] text-neutral-500 font-mono">
                You can run this exact command directly in your terminal to reproduce this request:
              </p>
              <pre className="p-3 bg-neutral-950 text-emerald-400 font-mono text-xs overflow-x-auto leading-relaxed border border-neutral-800 whitespace-pre-wrap">
                {result.curlCommand}
              </pre>
            </div>

            <div className="p-3 bg-blue-500/10 border border-blue-500/20 text-xs text-blue-900 dark:text-blue-300 font-sans space-y-1">
              <span className="font-semibold block font-mono text-[11px]">AUDIT LOG AUTOMATIC RECORDING</span>
              <p className="text-[11px] leading-relaxed">
                This request was dispatched to the Go proxy and recorded in <code>audit-logs/audit.jsonl</code>.
                You can switch to the <strong>Audit Log</strong> tab to inspect the persistent audit entry!
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Backend Deep-Dive Architecture Explainer */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-4">
        <div>
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide border-b border-neutral-200 dark:border-neutral-800 pb-2">
            Backend Architecture Deep Dive (How Every Major Component Works)
          </h2>
          <p className="text-[11px] text-neutral-500 font-mono mt-1">
            Technical explanation of Go packages, cryptographic handshakes, and container topology for viva questions
          </p>
        </div>

        {/* Sub-tabs */}
        <div className="flex border-b border-neutral-200 dark:border-neutral-800 gap-1 text-xs font-mono">
          {[
            { id: 'mtls', label: '1. mTLS (Mutual TLS)' },
            { id: 'opa', label: '2. OPA Policy Engine' },
            { id: 'oidc', label: '3. Keycloak OIDC' },
            { id: 'posture', label: '4. Device Posture' },
            { id: 'architecture', label: '5. Fail-Closed Model' },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setDeepDiveTab(t.id as any)}
              className={`px-3 py-2 font-medium transition ${
                deepDiveTab === t.id
                  ? 'border-b-2 border-blue-600 dark:border-blue-400 text-blue-600 dark:text-blue-400 bg-neutral-50 dark:bg-neutral-800/40'
                  : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-neutral-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="text-xs font-sans space-y-3 leading-relaxed text-neutral-800 dark:text-neutral-200">
          {deepDiveTab === 'mtls' && (
            <div className="space-y-3">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 font-mono text-[11px] space-y-1">
                <span className="font-semibold text-neutral-900 dark:text-neutral-100 block">
                  PACKAGE: `internal/mtls` | CERTIFICATES: `scripts/gen-certs.sh`
                </span>
                <p className="text-neutral-600 dark:text-neutral-400">
                  Mutual TLS secures communication between the Doorman Proxy and the upstream Backend Microservices (Backend A and B).
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-sans">
                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Standard TLS vs Mutual TLS (mTLS)
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    In standard TLS, only the client verifies the server's certificate. In <strong>mTLS</strong>, the server ALSO requires and cryptographically verifies the client's certificate.
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    If an attacker somehow breaches the internal container network and tries to call <code>http://backend-a:8080/</code> directly, the connection is immediately rejected because the attacker lacks the proxy's private key and internal CA signature.
                  </p>
                </div>

                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    How Certificates are Managed
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                    <li><strong>Internal CA (`certs/ca.crt`):</strong> Self-managed Root Certificate Authority.</li>
                    <li><strong>Proxy Client Cert (`certs/proxy-client.crt`):</strong> Issued to the proxy, renewed every 24 hours.</li>
                    <li><strong>Backend Server Cert (`certs/backend-a.crt`):</strong> Validated by proxy against Root CA.</li>
                    <li><strong>Hot-Reloading:</strong> `internal/mtls` reloads certificates on disk without proxy restarts.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {deepDiveTab === 'opa' && (
            <div className="space-y-3">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 font-mono text-[11px] space-y-1">
                <span className="font-semibold text-neutral-900 dark:text-neutral-100 block">
                  PACKAGE: `internal/policy` | RULES: `policies/authz.rego` | SERVICE: OPA REST on Port 8181
                </span>
                <p className="text-neutral-600 dark:text-neutral-400">
                  Open Policy Agent executes declarative authorization rules. Policies are completely decoupled from application code.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Core Rego Authorization Logic
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Every incoming request is evaluated against 4 deterministic safety boundaries:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                    <li><strong>Geo Fencing:</strong> Client country code must be in <code>policies/data.json</code> allowlist.</li>
                    <li><strong>Device Health:</strong> Disk must be encrypted, firewall active, patch age &lt; 30 days.</li>
                    <li><strong>Admin Privileges:</strong> Role `admin` allows full unrestricted CRUD access.</li>
                    <li><strong>Viewer Restrictions:</strong> Role `viewer` is restricted to read-only methods (GET/HEAD) outside `/admin` paths between 09:00-19:00.</li>
                  </ol>
                </div>

                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    In-Memory Decision Cache
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    To maintain the sub-12ms p95 latency SLA, `internal/policy` caches evaluation results using an SHA256 key composed of user, roles, resource, method, and device posture.
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Cache hits return in <strong>&lt; 0.5 ms</strong>, bypassing the REST HTTP roundtrip to OPA on port 8181!
                  </p>
                </div>
              </div>
            </div>
          )}

          {deepDiveTab === 'oidc' && (
            <div className="space-y-3">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 font-mono text-[11px] space-y-1">
                <span className="font-semibold text-neutral-900 dark:text-neutral-100 block">
                  PACKAGE: `internal/auth` | PROVIDER: Keycloak 25.0.6 (Port 8080) | REALM: `zt`
                </span>
                <p className="text-neutral-600 dark:text-neutral-400">
                  OpenID Connect handles identity verification. Every client authenticates and receives an asymmetric RS256 JWT.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    JWKS Cryptographic Verification
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Doorman does not store passwords or query databases. Instead, it pulls Keycloak's public keys via the JWKS endpoint (<code>/protocol/openid-connect/certs</code>).
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Every Bearer token's RS256 digital signature is verified locally using these cached public keys in under <strong>0.2 ms</strong>.
                  </p>
                </div>

                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Role-Based Access Control (RBAC)
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                    <li><strong>Alice (`admin`):</strong> Full privileges across all routes, bypassing time and path checks.</li>
                    <li><strong>Bob (`viewer`):</strong> Audited read-only viewer with strict business hour limits.</li>
                    <li><strong>Client Secret:</strong> `zt-proxy-dev-secret` authenticates confidential client credentials.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {deepDiveTab === 'posture' && (
            <div className="space-y-3">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 font-mono text-[11px] space-y-1">
                <span className="font-semibold text-neutral-900 dark:text-neutral-100 block">
                  PACKAGE: `internal/posture` | CLI AGENT: `cmd/posture-agent` | ALGORITHM: ECDSA ES256
                </span>
                <p className="text-neutral-600 dark:text-neutral-400">
                  Hardware and OS health attestation. Zero-Trust dictates: "Never trust user identity alone; verify device integrity."
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Why Posture is Critical
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Even if Alice's credentials are leaked, an attacker cannot access protected resources from an unauthorized or unencrypted machine.
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    The endpoint client runs <code>cmd/posture-agent</code>, inspects FileVault/BitLocker and firewall state, and cryptographically signs claims with an ECDSA private key.
                  </p>
                </div>

                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Verified Claims
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                    <li><code>disk_encrypted: true</code> (Prevents data extraction from stolen devices)</li>
                    <li><code>firewall_on: true</code> (Ensures host network defense)</li>
                    <li><code>os_patch_age_days: &lt;= 30</code> (Guarantees modern CVE security patches)</li>
                    <li><code>exp</code>: Short 5-minute expiry prevents replay attacks.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {deepDiveTab === 'architecture' && (
            <div className="space-y-3">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 font-mono text-[11px] space-y-1">
                <span className="font-semibold text-neutral-900 dark:text-neutral-100 block">
                  FAIL-CLOSED MODEL | REVERSE PROXY: `cmd/proxy` | AUDIT: `internal/audit`
                </span>
                <p className="text-neutral-600 dark:text-neutral-400">
                  Fail-closed guarantees that any system uncertainty, network partition, or missing token blocks access by default.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Fail-Closed Decision Gate
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    If OPA crashes, if Keycloak is unreachable, or if an invalid token is provided, Doorman returns <strong>HTTP 403 Forbidden</strong> rather than allowing access.
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Traditional proxies sometimes fail open when policy servers time out. Doorman strictly fails closed.
                  </p>
                </div>

                <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-2">
                  <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 font-mono text-xs">
                    Non-Blocking Asynchronous Audit Sink
                  </h4>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    Every decision (allow or deny) is dispatched to an internal Go buffered channel (capacity 10,000 items).
                  </p>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400">
                    A dedicated background worker routine flushes audit records to <code>audit-logs/audit.jsonl</code> and exports Prometheus metrics without adding I/O latency to the client's request!
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
