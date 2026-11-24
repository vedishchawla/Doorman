import React, { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';
import { fetchAuditEntries, formatLocalTimestamp } from '../api';
import { AuditEntry } from '../types';

interface AuditLedgerProps {
  refreshSignal?: number;
}

export const AuditLedger: React.FC<AuditLedgerProps> = ({ refreshSignal = 0 }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [isSample, setIsSample] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState<string>('');
  const [userFilter, setUserFilter] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadEntries = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchAuditEntries({
        decision: decisionFilter || undefined,
        user: userFilter.trim() || undefined,
      });
      setEntries(res.entries.slice(0, 30));
      setIsSample(res.isSample);
    } finally {
      setLoading(false);
    }
  }, [decisionFilter, userFilter]);

  useEffect(() => {
    loadEntries();
  }, [loadEntries, refreshSignal]);

  return (
    <section
      id="audit"
      className="surface-carbon bg-[#0E0F10] text-[#F4F3EE] border-b border-[#2A2D31] py-20 lg:py-28"
    >
      <div className="max-w-[1440px] mx-auto px-6 sm:px-10 lg:px-12">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-10 border-b border-[#2A2D31]">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#C8C4BA] mb-3">
              06 / ASYNC AUDIT LEDGER
            </div>
            <h2 className="font-serif text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] tracking-[-0.02em] text-[#F4F3EE]">
              Immutable Decision <em className="italic font-normal">Telemetry.</em>
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <span
              className={`px-2.5 py-1 border text-[10px] uppercase tracking-wider ${
                isSample
                  ? 'border-[#D97706] text-[#F59E0B] bg-[#33220D]'
                  : 'border-[#1B7F5C] text-[#2AC78A] bg-[#122E24]'
              }`}
            >
              {isSample ? 'SAMPLE LOG STREAM' : 'LIVE AUDIT.JSONL'}
            </span>
            <button
              type="button"
              onClick={loadEntries}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3 py-1.5 border border-[#3A3D42] hover:border-[#F4F3EE] text-[#F4F3EE] transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>REFRESH</span>
            </button>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="py-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#2A2D31]">
          <div className="flex border border-[#2A2D31] divide-x divide-[#2A2D31] bg-[#161719] self-start">
            {[
              { id: '', label: 'ALL' },
              { id: 'allow', label: 'ALLOW' },
              { id: 'deny', label: 'DENY' },
            ].map((opt) => (
              <button
                key={opt.id || 'all'}
                type="button"
                onClick={() => setDecisionFilter(opt.id)}
                className={`px-4 py-1.5 font-mono text-xs transition-colors ${
                  decisionFilter === opt.id
                    ? 'bg-[#F4F3EE] text-[#0E0F10] font-semibold'
                    : 'text-[#C8C4BA] hover:text-[#F4F3EE]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              placeholder="Filter by user (e.g. alice, bob)..."
              className="w-full sm:w-64 px-3 py-1.5 border border-[#2A2D31] bg-[#161719] font-mono text-xs text-[#F4F3EE] placeholder:text-[#8A877E]"
            />
          </div>
        </div>

        {/* Ledger Table */}
        <div className="overflow-x-auto border-x border-b border-[#2A2D31]">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#2A2D31] bg-[#161719] text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA]">
                <th className="py-3 px-4 w-8" />
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Identity</th>
                <th className="py-3 px-4">Request</th>
                <th className="py-3 px-4">Step</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Policy / Reason</th>
                <th className="py-3 px-4 text-right">Auth / OPA / Up (ms)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2D31]">
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-[#C8C4BA]">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                entries.map((entry, idx) => {
                  const rowKey = `${entry.request_id}-${idx}`;
                  const isOpen = expandedId === rowKey;
                  const isAllow = entry.decision === 'allow';
                  return (
                    <React.Fragment key={rowKey}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : rowKey)}
                        className="hover:bg-[#161719] cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 text-[#C8C4BA]">
                          {isOpen ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-3 px-4 tabular-nums text-[#C8C4BA] whitespace-nowrap">
                          {formatLocalTimestamp(entry.timestamp)}
                        </td>
                        <td className="py-3 px-4 text-[#F4F3EE] whitespace-nowrap">
                          {entry.user || <span className="text-[#A3A097]">(anon)</span>}
                          {entry.geo && (
                            <span className="ml-2 text-[10px] text-[#C8C4BA]">[{entry.geo}]</span>
                          )}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className="text-[#C8C4BA] mr-2">{entry.method}</span>
                          <span className="text-[#F4F3EE]">{entry.resource}</span>
                        </td>
                        <td className="py-3 px-4 tabular-nums text-[#E2DFD7]">
                          STEP {entry.step}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 text-[10px] uppercase border ${
                              isAllow
                                ? 'border-[#1B7F5C] bg-[#122E24] text-[#2AC78A]'
                                : 'border-[#E63B2E] bg-[#3B1614] text-[#FF6B5E]'
                            }`}
                          >
                            {entry.decision}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-[#E2DFD7] max-w-xs truncate">
                          {entry.policy_id ? (
                            <span>
                              <span className="text-[#FF6B5E] mr-1.5">{entry.policy_id}</span>
                              <span className="text-[#C8C4BA] font-sans">{entry.reason}</span>
                            </span>
                          ) : (
                            <span className="text-[#A3A097]">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right tabular-nums text-[#E2DFD7] whitespace-nowrap">
                          {entry.auth_ms.toFixed(2)} / {entry.opa_ms.toFixed(2)} /{' '}
                          {entry.upstream_ms.toFixed(2)}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[#161719]">
                          <td colSpan={8} className="p-4 border-t border-[#2A2D31]">
                            <pre className="text-[11px] text-[#E2DFD7] overflow-x-auto leading-relaxed">
                              {JSON.stringify(entry, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
