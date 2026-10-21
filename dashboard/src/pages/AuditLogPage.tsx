import React, { useEffect, useState } from 'react';
import { AuditEntry } from '../types';
import { fetchAuditEntries } from '../api';
import { StatusIndicator } from '../components/StatusIndicator';
import { SampleTag } from '../components/SampleTag';

export const AuditLogPage: React.FC = () => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [isSample, setIsSample] = useState(false);
  const [loading, setLoading] = useState(false);

  // Filter states
  const [userFilter, setUserFilter] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');

  // Selected entry for JSON inspector
  const [selectedEntry, setSelectedEntry] = useState<AuditEntry | null>(null);

  // Sort state
  const [sortField, setSortField] = useState<keyof AuditEntry>('timestamp');
  const [sortAsc, setSortAsc] = useState(false);

  const loadData = () => {
    setLoading(true);
    fetchAuditEntries({
      user: userFilter,
      decision: decisionFilter,
      resource: resourceFilter,
    }).then(({ entries, isSample }) => {
      setEntries(entries);
      setIsSample(isSample);
      setLoading(false);
    });
  };

  useEffect(() => {
    loadData();
  }, [userFilter, decisionFilter, resourceFilter]);

  const handleSort = (field: keyof AuditEntry) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default descending for new sort
    }
  };

  const sortedEntries = [...entries].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];

    if (aVal === undefined || aVal === null) aVal = '';
    if (bVal === undefined || bVal === null) bVal = '';

    if (typeof aVal === 'number' && typeof bVal === 'number') {
      return sortAsc ? aVal - bVal : bVal - aVal;
    }
    const aStr = String(aVal);
    const bStr = String(bVal);
    return sortAsc ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
  });

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <div>
          <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
            Audit Log Repository
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
            Query and inspect synchronous decision traces from /api/audit
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isSample && <SampleTag />}
          <span className="text-xs font-mono text-neutral-500">
            {sortedEntries.length} RECORDS MATCHED
          </span>
          <button
            onClick={loadData}
            className="px-2 py-1 text-xs font-mono border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-800 hover:border-neutral-400 dark:hover:border-neutral-600"
          >
            REFRESH
          </button>
        </div>
      </div>

      {/* Filter Toolbar - strictly functional, dense layout */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-neutral-600 dark:text-neutral-400 uppercase mb-1">
              Filter by User
            </label>
            <input
              type="text"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              placeholder="e.g. alice, bob"
              className="w-full text-xs font-mono px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 rounded-none"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-neutral-600 dark:text-neutral-400 uppercase mb-1">
              Filter by Decision
            </label>
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="w-full text-xs font-mono px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 rounded-none"
            >
              <option value="">ALL DECISIONS</option>
              <option value="allow">ALLOW</option>
              <option value="deny">DENY</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-mono text-neutral-600 dark:text-neutral-400 uppercase mb-1">
              Filter by Resource
            </label>
            <input
              type="text"
              value={resourceFilter}
              onChange={(e) => setResourceFilter(e.target.value)}
              placeholder="e.g. /admin, /backend-a"
              className="w-full text-xs font-mono px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 rounded-none"
            />
          </div>

          <div className="flex items-end gap-2">
            <button
              onClick={() => {
                setUserFilter('');
                setDecisionFilter('');
                setResourceFilter('');
              }}
              className="w-full text-xs font-mono py-1 px-2 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 hover:border-neutral-400 dark:hover:border-neutral-600"
            >
              RESET FILTERS
            </button>
          </div>
        </div>
      </div>

      {/* Main Dense Table */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
        {loading ? (
          <div className="p-4 text-xs font-mono text-neutral-500">Querying /api/audit...</div>
        ) : sortedEntries.length === 0 ? (
          <div className="p-4 text-xs font-mono text-neutral-500">
            No audit records match the current filter query.
          </div>
        ) : (
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 font-mono text-neutral-600 dark:text-neutral-400 select-none">
                <th
                  onClick={() => handleSort('timestamp')}
                  className="py-2 px-3 font-medium cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  TIMESTAMP {sortField === 'timestamp' && (sortAsc ? '▲' : '▼')}
                </th>
                <th
                  onClick={() => handleSort('step')}
                  className="py-2 px-2 font-medium cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  STEP {sortField === 'step' && (sortAsc ? '▲' : '▼')}
                </th>
                <th
                  onClick={() => handleSort('user')}
                  className="py-2 px-3 font-medium cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  USER {sortField === 'user' && (sortAsc ? '▲' : '▼')}
                </th>
                <th className="py-2 px-2 font-medium">METHOD</th>
                <th
                  onClick={() => handleSort('resource')}
                  className="py-2 px-3 font-medium cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  RESOURCE {sortField === 'resource' && (sortAsc ? '▲' : '▼')}
                </th>
                <th
                  onClick={() => handleSort('decision')}
                  className="py-2 px-3 font-medium cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  DECISION {sortField === 'decision' && (sortAsc ? '▲' : '▼')}
                </th>
                <th className="py-2 px-3 font-medium">REASON / POLICY ID</th>
                <th className="py-2 px-2 font-medium">CLIENT IP</th>
                <th className="py-2 px-2 font-medium">GEO</th>
                <th
                  onClick={() => handleSort('opa_ms')}
                  className="py-2 px-2 font-medium text-right cursor-pointer hover:text-neutral-900 dark:hover:text-neutral-200"
                >
                  OPA MS {sortField === 'opa_ms' && (sortAsc ? '▲' : '▼')}
                </th>
                <th className="py-2 px-2 font-medium text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 font-mono">
              {sortedEntries.map((e, idx) => (
                <tr
                  key={e.request_id || idx}
                  className={`hover:bg-neutral-50 dark:hover:bg-neutral-800/40 ${
                    selectedEntry?.request_id === e.request_id
                      ? 'bg-neutral-100 dark:bg-neutral-800/70 border-l-2 border-accent'
                      : ''
                  }`}
                >
                  <td className="py-2 px-3 text-neutral-500 text-[11px] whitespace-nowrap">
                    {e.timestamp ? e.timestamp.replace('T', ' ').substring(0, 19) : '-'}
                  </td>
                  <td className="py-2 px-2 text-neutral-600 dark:text-neutral-400">
                    <span className="px-1 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 text-[10px]">
                      S{e.step || 0}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-medium text-neutral-900 dark:text-neutral-100 whitespace-nowrap">
                    {e.user || <span className="text-neutral-400 font-normal">anonymous</span>}
                  </td>
                  <td className="py-2 px-2 text-neutral-700 dark:text-neutral-300 font-semibold">
                    {e.method}
                  </td>
                  <td className="py-2 px-3 text-neutral-800 dark:text-neutral-200 max-w-[200px] truncate" title={e.resource}>
                    {e.resource}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <StatusIndicator decision={e.decision} />
                  </td>
                  <td className="py-2 px-3 text-neutral-600 dark:text-neutral-400 max-w-[280px] truncate" title={e.reason || e.policy_id}>
                    {e.reason ? (
                      <span className="text-neutral-900 dark:text-neutral-100">{e.reason}</span>
                    ) : e.policy_id ? (
                      <span>{e.policy_id}</span>
                    ) : (
                      <span className="text-neutral-400">allow grant</span>
                    )}
                  </td>
                  <td className="py-2 px-2 text-neutral-600 dark:text-neutral-400 text-[11px] whitespace-nowrap">
                    {e.client_ip || '-'}
                  </td>
                  <td className="py-2 px-2 text-neutral-600 dark:text-neutral-400 text-[11px]">
                    {e.geo || '-'}
                  </td>
                  <td className="py-2 px-2 text-right text-neutral-700 dark:text-neutral-300">
                    {typeof e.opa_ms === 'number' ? e.opa_ms.toFixed(2) : '0.00'}
                  </td>
                  <td className="py-2 px-2 text-right">
                    <button
                      onClick={() => setSelectedEntry(selectedEntry?.request_id === e.request_id ? null : e)}
                      className="px-2 py-0.5 text-[10px] font-mono border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-800 hover:border-neutral-400 dark:hover:border-neutral-600 text-neutral-800 dark:text-neutral-200"
                    >
                      {selectedEntry?.request_id === e.request_id ? 'CLOSE' : 'INSPECT'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* JSON Inspector for selected row */}
      {selectedEntry && (
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4">
          <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2 mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-semibold text-neutral-900 dark:text-neutral-100">
                AUDIT RECORD DETAIL: {selectedEntry.request_id}
              </span>
              <StatusIndicator decision={selectedEntry.decision} />
            </div>
            <button
              onClick={() => setSelectedEntry(null)}
              className="text-xs font-mono px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 hover:bg-neutral-200 dark:hover:bg-neutral-700"
            >
              CLOSE INSPECTOR
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-3 text-xs font-mono">
            <div>
              <span className="text-neutral-500 block text-[10px]">AUTH STAGE MS</span>
              <span className="text-neutral-900 dark:text-neutral-100">{selectedEntry.auth_ms} ms</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px]">OPA EVAL MS</span>
              <span className="text-neutral-900 dark:text-neutral-100">{selectedEntry.opa_ms} ms</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px]">UPSTREAM MTLS MS</span>
              <span className="text-neutral-900 dark:text-neutral-100">{selectedEntry.upstream_ms} ms</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px]">DEVICE ID</span>
              <span className="text-neutral-900 dark:text-neutral-100">{selectedEntry.device_id || 'NONE'}</span>
            </div>
          </div>
          <pre className="p-3 bg-neutral-100 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-800 dark:text-neutral-200 overflow-x-auto">
            {JSON.stringify(selectedEntry, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
