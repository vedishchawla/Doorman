import React, { useEffect, useState } from 'react';
import { AuditEntry, PageId } from '../types';
import { fetchAuditEntries, formatLocalTimestamp } from '../api';
import { StatusIndicator } from '../components/StatusIndicator';
import { SampleTag } from '../components/SampleTag';

interface Props {
  onNavigate?: (page: PageId) => void;
}

export const OverviewPage: React.FC<Props> = ({ onNavigate }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [isSample, setIsSample] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchAuditEntries().then(({ entries, isSample }) => {
      if (mounted) {
        setEntries(entries);
        setIsSample(isSample);
        setLoading(false);
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  // Compute metrics from actual entries
  const total = entries.length;
  const allowCount = entries.filter((e) => e.decision.toLowerCase() === 'allow').length;
  const denyCount = entries.filter((e) => e.decision.toLowerCase() === 'deny').length;
  const allowRate = total > 0 ? ((allowCount / total) * 100).toFixed(1) : '0.0';

  // Calculate p95 latencies
  const calcP95 = (values: number[]) => {
    if (values.length === 0) return '0.00';
    const sorted = [...values].sort((a, b) => a - b);
    const idx = Math.floor(sorted.length * 0.95);
    return sorted[Math.min(idx, sorted.length - 1)].toFixed(2);
  };

  const p95Auth = calcP95(entries.map((e) => e.auth_ms || 0));
  const p95Opa = calcP95(entries.map((e) => e.opa_ms || 0));
  const p95Upstream = calcP95(entries.map((e) => e.upstream_ms || 0));

  const components = [
    { name: 'Proxy Ingress', pkg: 'cmd/proxy', status: 'ONLINE', port: '8080/443', detail: 'Fail-closed routing, TLS termination' },
    { name: 'Keycloak OIDC', pkg: 'internal/auth', status: 'ONLINE', port: '8080/9000', detail: 'Realm zt (RS256 JWT, JWKS verification)' },
    { name: 'Open Policy Agent', pkg: 'internal/policy', status: 'ONLINE', port: '8181', detail: 'Package zt.authz (Rego policy engine)' },
    { name: 'Backend A', pkg: 'internal/mtls', status: 'ONLINE', port: '8080', detail: 'mTLS verification required (24h certs)' },
    { name: 'Backend B', pkg: 'internal/mtls', status: 'ONLINE', port: '8080', detail: 'mTLS verification required (24h certs)' },
    { name: 'Audit Log Sink', pkg: 'internal/audit', status: 'ONLINE', port: 'local/fs', detail: 'audit-logs/audit.jsonl & Prometheus :9090' },
  ];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <div>
          <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
            System Overview
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
            Status of ingress pipeline, active verification stages, and runtime statistics
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isSample && <SampleTag />}
          <span className="text-xs font-mono text-neutral-500 dark:text-neutral-400">
            LOADED {total} RECORDS
          </span>
        </div>
      </div>

      {/* Primary KPI metrics strip - dense, tabular format, no cards with left borders */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 border border-neutral-300 dark:border-neutral-800 divide-x divide-y md:divide-y-0 divide-neutral-300 dark:divide-neutral-800 bg-white dark:bg-neutral-900 text-xs">
        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">TOTAL REQUESTS</div>
          <div className="text-lg font-mono font-semibold text-neutral-900 dark:text-neutral-100 mt-1">
            {total}
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">
            {isSample ? 'Sample baseline' : 'From /api/audit'}
          </div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">ALLOW RATE</div>
          <div className="text-lg font-mono font-semibold text-status-allow dark:text-status-allow-dark mt-1">
            {allowRate}%
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">{allowCount} allowed</div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">DENIAL COUNT</div>
          <div className="text-lg font-mono font-semibold text-status-deny dark:text-status-deny-dark mt-1">
            {denyCount}
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">Policy/Auth failures</div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">AUTH P95</div>
          <div className="text-lg font-mono font-semibold text-neutral-900 dark:text-neutral-100 mt-1">
            {p95Auth} ms
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">OIDC validation</div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">OPA P95</div>
          <div className="text-lg font-mono font-semibold text-neutral-900 dark:text-neutral-100 mt-1">
            {p95Opa} ms
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">Target: &lt; 12 ms</div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">UPSTREAM P95</div>
          <div className="text-lg font-mono font-semibold text-neutral-900 dark:text-neutral-100 mt-1">
            {p95Upstream} ms
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">mTLS roundtrip</div>
        </div>

        <div className="p-3">
          <div className="text-neutral-500 dark:text-neutral-400 font-mono text-[11px]">POLICY ENGINE</div>
          <div className="text-lg font-mono font-semibold text-accent mt-1">
            FAIL-CLOSED
          </div>
          <div className="text-[11px] text-neutral-500 font-mono mt-1">Strict evaluation</div>
        </div>
      </div>

      {/* 7-Step Pipeline Flow Diagram Bar */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-2">
          <div>
            <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
              Zero-Trust Verification Pipeline (7 Stages)
            </h2>
            <p className="text-[11px] text-neutral-500 font-mono mt-0.5">
              Every request to microservices undergoes this sequential evaluation
            </p>
          </div>
          {onNavigate && (
            <button
              onClick={() => onNavigate('simulator')}
              className="px-3 py-1 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white font-mono text-xs font-semibold transition flex items-center gap-1.5 self-start sm:self-auto"
            >
              <span>▶ LAUNCH INTERACTIVE SIMULATOR</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 text-xs font-mono">
          {[
            { step: 1, name: 'Request Ingress', pkg: 'nginx / proxy', desc: 'TLS termination' },
            { step: 2, name: 'OIDC Identity', pkg: 'internal/auth', desc: 'Keycloak RS256' },
            { step: 3, name: 'Device Posture', pkg: 'internal/posture', desc: 'ES256 hardware' },
            { step: 4, name: 'OPA Evaluation', pkg: 'internal/policy', desc: 'Rego REST rules' },
            { step: 5, name: 'Decision Gate', pkg: 'cmd/proxy', desc: 'Fail-closed logic' },
            { step: 6, name: 'mTLS Upstream', pkg: 'internal/mtls', desc: 'Client certs (24h)' },
            { step: 7, name: 'Async Audit', pkg: 'internal/audit', desc: 'JSONL & :9090' },
          ].map((st) => (
            <div
              key={st.step}
              className="p-2 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between text-[10px] text-neutral-500 font-bold mb-1">
                  <span>STEP {st.step}</span>
                  <span className="text-emerald-600 dark:text-emerald-400">ACTIVE</span>
                </div>
                <div className="font-semibold text-neutral-900 dark:text-neutral-100 text-[11px] leading-tight">
                  {st.name}
                </div>
              </div>
              <div className="mt-2 pt-1 border-t border-neutral-200 dark:border-neutral-800 text-[10px] text-neutral-500 flex flex-col">
                <span className="text-neutral-600 dark:text-neutral-400 font-mono truncate">{st.pkg}</span>
                <span className="text-[9px] text-neutral-400 truncate">{st.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Infrastructure Components Table */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            Subsystem Infrastructure Status
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">6 COMPONENTS MONITORED</span>
        </div>
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/60 font-mono text-neutral-600 dark:text-neutral-400">
                <th className="py-2 px-3 font-medium">COMPONENT</th>
                <th className="py-2 px-3 font-medium">GO PACKAGE</th>
                <th className="py-2 px-3 font-medium">STATUS</th>
                <th className="py-2 px-3 font-medium">BIND PORT</th>
                <th className="py-2 px-3 font-medium">SPECIFICATION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 font-mono">
              {components.map((c) => (
                <tr key={c.name} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                  <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">{c.name}</td>
                  <td className="py-2 px-3 text-neutral-500 text-[11px]">`{c.pkg}`</td>
                  <td className="py-2 px-3">
                    <span className="inline-flex items-center gap-1 text-status-allow dark:text-status-allow-dark">
                      <span className="w-1.5 h-1.5 bg-status-allow dark:bg-status-allow-dark inline-block"></span>
                      {c.status}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-neutral-600 dark:text-neutral-400">{c.port}</td>
                  <td className="py-2 px-3 text-neutral-700 dark:text-neutral-300">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Traffic Table */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            Recent Audit Stream (Latest 10 Requests)
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">POLL: /api/audit</span>
        </div>
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          {loading ? (
            <div className="p-4 text-xs font-mono text-neutral-500">Loading audit records...</div>
          ) : entries.length === 0 ? (
            <div className="p-4 text-xs font-mono text-neutral-500">No records found.</div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/60 font-mono text-neutral-600 dark:text-neutral-400">
                  <th className="py-2 px-3 font-medium">TIMESTAMP</th>
                  <th className="py-2 px-3 font-medium">USER</th>
                  <th className="py-2 px-3 font-medium">METHOD</th>
                  <th className="py-2 px-3 font-medium">RESOURCE</th>
                  <th className="py-2 px-3 font-medium">DECISION</th>
                  <th className="py-2 px-3 font-medium">POLICY ID / REASON</th>
                  <th className="py-2 px-3 font-medium text-right">OPA MS</th>
                  <th className="py-2 px-3 font-medium text-right">TOTAL MS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 font-mono">
                {entries.slice(0, 10).map((e, idx) => {
                  const totalMs = ((e.auth_ms || 0) + (e.opa_ms || 0) + (e.upstream_ms || 0)).toFixed(2);
                  return (
                    <tr key={idx} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                      <td className="py-2 px-3 text-neutral-500 text-[11px] whitespace-nowrap" title={e.timestamp ? `UTC: ${e.timestamp}` : ''}>
                        {formatLocalTimestamp(e.timestamp)}
                      </td>
                      <td className="py-2 px-3 text-neutral-900 dark:text-neutral-100">
                        {e.user || <span className="text-neutral-400">anonymous</span>}
                      </td>
                      <td className="py-2 px-3 text-neutral-700 dark:text-neutral-300">{e.method}</td>
                      <td className="py-2 px-3 text-neutral-800 dark:text-neutral-200">{e.resource}</td>
                      <td className="py-2 px-3">
                        <StatusIndicator decision={e.decision} />
                      </td>
                      <td className="py-2 px-3 text-neutral-600 dark:text-neutral-400">
                        {e.reason ? (
                          <span className="text-neutral-700 dark:text-neutral-300">{e.reason}</span>
                        ) : e.policy_id ? (
                          <span>{e.policy_id}</span>
                        ) : (
                          <span className="text-neutral-400">explicit grant</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-right text-neutral-700 dark:text-neutral-300">
                        {e.opa_ms ? e.opa_ms.toFixed(2) : '0.00'}
                      </td>
                      <td className="py-2 px-3 text-right font-medium text-neutral-900 dark:text-neutral-100">
                        {totalMs}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
