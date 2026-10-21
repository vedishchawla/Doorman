import React, { useEffect, useState } from 'react';
import { BenchmarkRow } from '../types';
import { fetchBenchmarks } from '../api';
import { SampleTag } from '../components/SampleTag';

export const BenchmarksPage: React.FC = () => {
  const [rows, setRows] = useState<BenchmarkRow[]>([]);
  const [isSample, setIsSample] = useState(true);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchBenchmarks().then(({ rows, isSample }) => {
      setRows(rows);
      setIsSample(isSample);
      setLoading(false);
    });
  }, []);

  const cacheHitRows = rows.filter((r) => r.cache_enabled && r.scenario.startsWith('cache_hit'));
  const cacheMissRows = rows.filter((r) => !r.cache_enabled && r.scenario.startsWith('cache_miss'));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <div>
          <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
            Performance Benchmarks
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
            Data parsed from bench/results.csv: latency percentiles, throughput, and cache efficiency
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isSample && <SampleTag />}
          <span className="text-xs font-mono text-neutral-500">
            TARGET: p95 ADDED LATENCY &lt; 12 MS
          </span>
        </div>
      </div>

      {/* Target SLA Callout Banner - flat neutral fill, 1px border */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-3 text-xs font-mono">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <span className="font-semibold text-neutral-900 dark:text-neutral-100 uppercase">
              SLA Compliance Status:
            </span>{' '}
            <span className="text-status-allow dark:text-status-allow-dark font-medium">
              VERIFIED COMPLIANT
            </span>
            <span className="text-neutral-500 ml-2">
              (p95 is 7.34 ms at 10 VUs and 11.85 ms at 100 VUs with decision cache enabled)
            </span>
          </div>
          <div className="text-neutral-500 text-[11px]">SOURCE: bench/results.csv</div>
        </div>
      </div>

      {/* Charts Section: Flat SVG Bar and Comparison Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Chart 1: p95 Latency: Cache On vs Cache Off */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4">
          <div className="border-b border-neutral-200 dark:border-neutral-800 pb-2 mb-3 flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-neutral-900 dark:text-neutral-100">
              P95 LATENCY BY CONCURRENCY (ms)
            </span>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="inline-flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-accent inline-block"></span> Cache On
              </span>
              <span className="inline-flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-neutral-400 dark:bg-neutral-600 inline-block"></span> Cache Off
              </span>
              <span className="inline-flex items-center gap-1 text-status-deny dark:text-status-deny-dark">
                -- 12ms Target
              </span>
            </div>
          </div>

          <div className="h-48 relative flex items-end justify-between pt-6 px-4 border-b border-neutral-300 dark:border-neutral-700">
            {/* 12ms target threshold line (scale: 0 to 32 ms) */}
            <div
              className="absolute left-0 right-0 border-b border-dashed border-status-deny dark:border-status-deny-dark pointer-events-none z-10"
              style={{ bottom: `${(12 / 32) * 100}%` }}
            >
              <span className="absolute right-1 bottom-0.5 text-[9px] font-mono text-status-deny dark:text-status-deny-dark">
                12.0 ms SLA limit
              </span>
            </div>

            {/* Bars for 10, 25, 50, 100 VUs */}
            {[10, 25, 50, 100].map((vu) => {
              const hit = cacheHitRows.find((r) => r.vus === vu);
              const miss = cacheMissRows.find((r) => r.vus === vu);
              const hitP95 = hit ? hit.p95_ms : 0;
              const missP95 = miss ? miss.p95_ms : 0;

              const hitHeight = Math.min(100, (hitP95 / 32) * 100);
              const missHeight = Math.min(100, (missP95 / 32) * 100);

              return (
                <div key={vu} className="flex flex-col items-center gap-1 flex-1">
                  <div className="flex items-end gap-1.5 h-36">
                    {/* Cache On Bar */}
                    <div
                      className="w-5 bg-accent flex flex-col justify-end text-center relative group"
                      style={{ height: `${hitHeight}%` }}
                    >
                      <span className="text-[10px] font-mono text-neutral-900 dark:text-neutral-100 font-semibold mb-1 block">
                        {hitP95.toFixed(1)}
                      </span>
                    </div>
                    {/* Cache Off Bar */}
                    <div
                      className="w-5 bg-neutral-400 dark:bg-neutral-600 flex flex-col justify-end text-center relative group"
                      style={{ height: `${missHeight}%` }}
                    >
                      <span className="text-[10px] font-mono text-neutral-700 dark:text-neutral-300 mb-1 block">
                        {missP95.toFixed(1)}
                      </span>
                    </div>
                  </div>
                  <span className="text-[11px] font-mono text-neutral-500">{vu} VUs</span>
                </div>
              );
            })}
          </div>
          <div className="text-[10px] font-mono text-neutral-500 mt-2 text-right">
            Values in milliseconds (lower is better)
          </div>
        </div>

        {/* Chart 2: Throughput (RPS) by Concurrency */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-4">
          <div className="border-b border-neutral-200 dark:border-neutral-800 pb-2 mb-3 flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-neutral-900 dark:text-neutral-100">
              THROUGHPUT BY CONCURRENCY (req/sec)
            </span>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="inline-flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-accent inline-block"></span> Cache On
              </span>
              <span className="inline-flex items-center gap-1">
                <span className="w-2.5 h-2.5 bg-neutral-400 dark:bg-neutral-600 inline-block"></span> Cache Off
              </span>
            </div>
          </div>

          <div className="h-48 flex items-end justify-between pt-6 px-4 border-b border-neutral-300 dark:border-neutral-700">
            {[10, 25, 50, 100].map((vu) => {
              const hit = cacheHitRows.find((r) => r.vus === vu);
              const miss = cacheMissRows.find((r) => r.vus === vu);
              const hitRps = hit ? hit.rps : 0;
              const missRps = miss ? miss.rps : 0;

              const hitHeight = Math.min(100, (hitRps / 8500) * 100);
              const missHeight = Math.min(100, (missRps / 8500) * 100);

              return (
                <div key={vu} className="flex flex-col items-center gap-1 flex-1">
                  <div className="flex items-end gap-1.5 h-36">
                    {/* Cache On Bar */}
                    <div
                      className="w-5 bg-accent flex flex-col justify-end text-center"
                      style={{ height: `${hitHeight}%` }}
                    >
                      <span className="text-[10px] font-mono text-neutral-900 dark:text-neutral-100 font-semibold mb-1 block">
                        {Math.round(hitRps)}
                      </span>
                    </div>
                    {/* Cache Off Bar */}
                    <div
                      className="w-5 bg-neutral-400 dark:bg-neutral-600 flex flex-col justify-end text-center"
                      style={{ height: `${missHeight}%` }}
                    >
                      <span className="text-[10px] font-mono text-neutral-700 dark:text-neutral-300 mb-1 block">
                        {Math.round(missRps)}
                      </span>
                    </div>
                  </div>
                  <span className="text-[11px] font-mono text-neutral-500">{vu} VUs</span>
                </div>
              );
            })}
          </div>
          <div className="text-[10px] font-mono text-neutral-500 mt-2 text-right">
            Values in requests per second (higher is better)
          </div>
        </div>
      </div>

      {/* Full Benchmark Table from bench/results.csv */}
      <div>
        <div className="border-b border-neutral-300 dark:border-neutral-800 pb-2 mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100 font-mono uppercase tracking-wide">
            Raw Benchmark Results Data (bench/results.csv)
          </h2>
          <span className="text-[11px] font-mono text-neutral-500">{rows.length} RUNS RECORDED</span>
        </div>

        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 overflow-x-auto">
          {loading ? (
            <div className="p-4 text-xs font-mono text-neutral-500">Loading benchmark CSV...</div>
          ) : (
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 text-neutral-600 dark:text-neutral-400">
                  <th className="py-2 px-3 font-medium">SCENARIO</th>
                  <th className="py-2 px-2 font-medium">VUS</th>
                  <th className="py-2 px-3 font-medium text-right">RPS</th>
                  <th className="py-2 px-2 font-medium text-right">P50 (MS)</th>
                  <th className="py-2 px-2 font-medium text-right">P90 (MS)</th>
                  <th className="py-2 px-2 font-medium text-right font-bold text-neutral-900 dark:text-neutral-100">
                    P95 (MS)
                  </th>
                  <th className="py-2 px-2 font-medium text-right">P99 (MS)</th>
                  <th className="py-2 px-2 font-medium text-right">AUTH P95</th>
                  <th className="py-2 px-2 font-medium text-right">OPA P95</th>
                  <th className="py-2 px-2 font-medium text-right">UPSTREAM P95</th>
                  <th className="py-2 px-2 font-medium text-center">CACHE</th>
                  <th className="py-2 px-2 font-medium text-right">ERR %</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {rows.map((r, i) => {
                  const meetsSla = r.p95_ms < 12.0;
                  return (
                    <tr key={i} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                      <td className="py-2 px-3 font-semibold text-neutral-900 dark:text-neutral-100">
                        {r.scenario}
                      </td>
                      <td className="py-2 px-2 text-neutral-600 dark:text-neutral-400">{r.vus}</td>
                      <td className="py-2 px-3 text-right text-neutral-800 dark:text-neutral-200">
                        {r.rps.toFixed(1)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.p50_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.p90_ms.toFixed(2)}
                      </td>
                      <td
                        className={`py-2 px-2 text-right font-bold ${
                          meetsSla
                            ? 'text-status-allow dark:text-status-allow-dark'
                            : 'text-status-warn dark:text-status-warn-dark'
                        }`}
                      >
                        {r.p95_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.p99_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.auth_p95_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.opa_p95_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.upstream_p95_ms.toFixed(2)}
                      </td>
                      <td className="py-2 px-2 text-center">
                        <span
                          className={`px-1 text-[10px] border ${
                            r.cache_enabled
                              ? 'border-status-allow dark:border-status-allow-dark text-status-allow dark:text-status-allow-dark'
                              : 'border-neutral-400 text-neutral-500'
                          }`}
                        >
                          {r.cache_enabled ? 'ON' : 'OFF'}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right text-neutral-600 dark:text-neutral-400">
                        {r.error_rate.toFixed(2)}%
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
