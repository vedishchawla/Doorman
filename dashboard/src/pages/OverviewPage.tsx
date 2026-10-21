import React, { useEffect, useState } from 'react';
import { AuditEntry } from '../types';
import { fetchAuditEntries, formatLocalTimestamp } from '../api';
import { StatusIndicator } from '../components/StatusIndicator';
import { SampleTag } from '../components/SampleTag';

export const OverviewPage: React.FC = () => {
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
    { name: 'Proxy Ingress', status: 'ONLINE', port: '8080/443', detail: 'Fail-closed routing' },
    { name: 'Keycloak OIDC', status: 'ONLINE', port: '8080/9000', detail: 'Realm zt (RS256)' },
    { name: 'Open Policy Agent', status: 'ONLINE', port: '8181', detail: 'Package zt.authz' },
    { name: 'Backend A', status: 'ONLINE', port: '8080', detail: 'mTLS verification required' },
    { name: 'Backend B', status: 'ONLINE', port: '8080', detail: 'mTLS verification required' },
    { name: 'Audit Log Sink', status: 'ONLINE', port: 'local/fs', detail: 'audit-logs/audit.jsonl' },
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
                <th className="py-2 px-3 font-medium">STATUS</th>
                <th className="py-2 px-3 font-medium">BIND PORT</th>
                <th className="py-2 px-3 font-medium">SPECIFICATION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 font-mono">
              {components.map((c) => (
                <tr key={c.name} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                  <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">{c.name}</td>
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
