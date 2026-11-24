import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { fetchBenchmarks } from '../api';
import { BenchmarkRow } from '../types';

gsap.registerPlugin(ScrollTrigger);

export const BenchmarkPlot: React.FC = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const slaLineRef = useRef<SVGLineElement>(null);
  const [rows, setRows] = useState<BenchmarkRow[]>([]);
  const [selectedVu, setSelectedVu] = useState<number>(100);

  useEffect(() => {
    fetchBenchmarks().then(({ rows: loaded }) => {
      setRows(loaded);
    });
  }, []);

  useEffect(() => {
    const ctx = gsap.context(() => {
      const mm = gsap.matchMedia();
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        if (slaLineRef.current) {
          gsap.fromTo(
            slaLineRef.current,
            { strokeDashoffset: 900 },
            {
              strokeDashoffset: 0,
              duration: 1.1,
              ease: 'expo.out',
              scrollTrigger: {
                trigger: sectionRef.current,
                start: 'top 75%',
                once: true,
              },
            }
          );
        }
      });
    }, sectionRef);
    return () => ctx.revert();
  }, [rows.length]);

  const cacheOn = rows.filter((r) => r.cache_enabled).sort((a, b) => a.vus - b.vus);
  const cacheOff = rows.filter((r) => !r.cache_enabled).sort((a, b) => a.vus - b.vus);
  const vuSteps = Array.from(new Set(rows.map((r) => r.vus))).sort((a, b) => a - b);

  const selectedOn = cacheOn.find((r) => r.vus === selectedVu) || cacheOn[cacheOn.length - 1];
  const selectedOff = cacheOff.find((r) => r.vus === selectedVu) || cacheOff[cacheOff.length - 1];

  const svgW = 760;
  const svgH = 320;
  const padL = 56;
  const padR = 28;
  const padT = 24;
  const padB = 42;
  const plotW = svgW - padL - padR;
  const plotH = svgH - padT - padB;
  const maxY = 32;

  const xForIndex = (idx: number, len: number) =>
    len <= 1 ? padL : padL + (idx / (len - 1)) * plotW;
  const yForMs = (ms: number) => padT + plotH - Math.min(1, Math.max(0, ms / maxY)) * plotH;

  const buildPath = (pts: BenchmarkRow[]) =>
    pts
      .map(
        (pt, i) =>
          `${i === 0 ? 'M' : 'L'} ${xForIndex(i, pts.length).toFixed(1)} ${yForMs(pt.p95_ms).toFixed(1)}`
      )
      .join(' ');

  const slaY = yForMs(12);

  return (
    <section
      id="bench"
      ref={sectionRef}
      className="surface-bone bg-[#F4F3EE] text-[#141413] border-b border-[#C9C5BA] py-20 lg:py-28"
    >
      <div className="max-w-[1440px] mx-auto px-6 sm:px-10 lg:px-12">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-10 border-b border-[#C9C5BA]">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#3D3C38] mb-3">
              05 / K6 PERFORMANCE BENCHMARKS
            </div>
            <h2 className="font-serif text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] tracking-[-0.02em] text-[#141413]">
              Sub-12ms SLA Under <em className="italic font-normal">100 Virtual Users.</em>
            </h2>
          </div>
          <p className="max-w-md font-sans text-sm text-[#3D3C38] leading-relaxed">
            Comparative p95 latency loaded directly from{' '}
            <code className="text-[#141413] bg-[#EAE8E0] px-1">bench/results.csv</code>. In-memory
            OPA decision caching removes repeated REST roundtrips and sustains 7,820 rps at 11.85 ms
            p95.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-10">
          {/* Chart Canvas (8 cols) */}
          <div className="lg:col-span-8 border border-[#C9C5BA] bg-[#EAE8E0] p-6">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6 font-mono text-xs">
              <div className="flex items-center gap-6">
                <span className="inline-flex items-center gap-2">
                  <span className="w-3 h-0.5 bg-[#1B7F5C] inline-block" />
                  <span className="text-[#141413] font-medium">
                    OPA Cache ON (7.34–11.85 ms)
                  </span>
                </span>
                <span className="inline-flex items-center gap-2">
                  <span className="w-3 h-0.5 bg-[#E63B2E] inline-block" />
                  <span className="text-[#141413] font-medium">
                    OPA Cache OFF (13.80–29.10 ms)
                  </span>
                </span>
              </div>
              <span className="text-[#3D3C38] uppercase text-[11px]">Select VU Load Point</span>
            </div>

            <div className="w-full overflow-x-auto">
              <svg
                viewBox={`0 0 ${svgW} ${svgH}`}
                className="w-full min-w-[540px] h-auto overflow-visible font-mono"
                role="img"
                aria-label="p95 latency comparison between OPA cache enabled and disabled"
              >
                {[0, 8, 12, 16, 24, 32].map((val) => {
                  const y = yForMs(val);
                  return (
                    <g key={val}>
                      <line
                        x1={padL}
                        y1={y}
                        x2={svgW - padR}
                        y2={y}
                        stroke={val === 12 ? 'transparent' : '#C9C5BA'}
                        strokeWidth="1"
                      />
                      <text x={padL - 10} y={y + 4} textAnchor="end" fill="#3D3C38" fontSize="10">
                        {val}ms
                      </text>
                    </g>
                  );
                })}

                <line
                  ref={slaLineRef}
                  x1={padL}
                  y1={slaY}
                  x2={svgW - padR}
                  y2={slaY}
                  stroke="#141413"
                  strokeWidth="1.5"
                  strokeDasharray="6 4"
                />
                <text
                  x={svgW - padR}
                  y={slaY - 7}
                  textAnchor="end"
                  fill="#141413"
                  fontSize="10"
                  fontWeight="600"
                >
                  12.00 MS SLA CEILING
                </text>

                {cacheOff.length > 1 && (
                  <path d={buildPath(cacheOff)} fill="none" stroke="#E63B2E" strokeWidth="2.5" />
                )}

                {cacheOn.length > 1 && (
                  <path d={buildPath(cacheOn)} fill="none" stroke="#1B7F5C" strokeWidth="2.5" />
                )}

                {vuSteps.map((vu, idx) => {
                  const x = xForIndex(idx, vuSteps.length);
                  const onPt = cacheOn.find((r) => r.vus === vu);
                  const offPt = cacheOff.find((r) => r.vus === vu);
                  const isSel = vu === selectedVu;

                  return (
                    <g key={vu} className="cursor-pointer" onClick={() => setSelectedVu(vu)}>
                      {isSel && (
                        <line
                          x1={x}
                          y1={padT}
                          x2={x}
                          y2={svgH - padB}
                          stroke="#141413"
                          strokeOpacity="0.3"
                          strokeWidth="1"
                        />
                      )}

                      {offPt && (
                        <circle
                          cx={x}
                          cy={yForMs(offPt.p95_ms)}
                          r={isSel ? 5.5 : 4}
                          fill="#E63B2E"
                          stroke="#F4F3EE"
                          strokeWidth="1.5"
                        />
                      )}

                      {onPt && (
                        <circle
                          cx={x}
                          cy={yForMs(onPt.p95_ms)}
                          r={isSel ? 5.5 : 4}
                          fill="#1B7F5C"
                          stroke="#F4F3EE"
                          strokeWidth="1.5"
                        />
                      )}

                      <text
                        x={x}
                        y={svgH - 14}
                        textAnchor="middle"
                        fill={isSel ? '#141413' : '#3D3C38'}
                        fontWeight={isSel ? '700' : '400'}
                        fontSize="11"
                      >
                        {vu} VUs
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* VU Selector Pills */}
            <div className="mt-4 pt-4 border-t border-[#C9C5BA] flex flex-wrap items-center justify-between gap-3">
              <span className="font-mono text-[11px] text-[#3D3C38]">
                Inspect Concurrency Tier:
              </span>
              <div className="flex border border-[#C9C5BA] divide-x divide-[#C9C5BA] bg-[#F4F3EE]">
                {vuSteps.map((vu) => (
                  <button
                    key={vu}
                    type="button"
                    onClick={() => setSelectedVu(vu)}
                    className={`px-3.5 py-1.5 font-mono text-xs tabular-nums transition-colors ${
                      selectedVu === vu
                        ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                        : 'text-[#3D3C38] hover:text-[#141413]'
                    }`}
                  >
                    {vu} VUs
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Telemetry Breakdown Inspector (4 cols) */}
          <div className="lg:col-span-4 border border-[#2A2D31] surface-carbon bg-[#0E0F10] text-[#F4F3EE] p-6 flex flex-col justify-between gap-6">
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#C8C4BA]">
                Selected Load Tier
              </div>
              <div className="font-serif text-4xl text-[#F4F3EE] mt-1 tabular-nums">
                {selectedVu} Virtual Users
              </div>
            </div>

            {selectedOn && selectedOff && (
              <div className="space-y-5 font-mono">
                <div className="border border-[#1B7F5C] bg-[#122E24] p-4">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-[#2AC78A] uppercase font-semibold">OPA Cache ON</span>
                    <span className="text-[#2AC78A] tabular-nums">
                      {selectedOn.rps.toFixed(0)} rps
                    </span>
                  </div>
                  <div className="text-2xl font-semibold text-[#F4F3EE] tabular-nums mt-1">
                    {selectedOn.p95_ms.toFixed(2)} ms{' '}
                    <span className="text-xs font-normal text-[#C8C4BA]">p95</span>
                  </div>
                  <div className="mt-3 pt-3 border-t border-[#1B7F5C]/40 grid grid-cols-3 gap-2 text-[10px] text-[#E2DFD7] tabular-nums">
                    <div>Auth: {selectedOn.auth_p95_ms}ms</div>
                    <div>OPA: {selectedOn.opa_p95_ms}ms</div>
                    <div>mTLS: {selectedOn.upstream_p95_ms}ms</div>
                  </div>
                </div>

                <div className="border border-[#E63B2E] bg-[#3B1614] p-4">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-[#FF6B5E] uppercase font-semibold">OPA Cache OFF</span>
                    <span className="text-[#FF6B5E] tabular-nums">
                      {selectedOff.rps.toFixed(0)} rps
                    </span>
                  </div>
                  <div className="text-2xl font-semibold text-[#F4F3EE] tabular-nums mt-1">
                    {selectedOff.p95_ms.toFixed(2)} ms{' '}
                    <span className="text-xs font-normal text-[#C8C4BA]">p95</span>
                  </div>
                  <div className="mt-3 pt-3 border-t border-[#E63B2E]/40 grid grid-cols-3 gap-2 text-[10px] text-[#E2DFD7] tabular-nums">
                    <div>Auth: {selectedOff.auth_p95_ms}ms</div>
                    <div>OPA: {selectedOff.opa_p95_ms}ms</div>
                    <div>mTLS: {selectedOff.upstream_p95_ms}ms</div>
                  </div>
                </div>

                <div className="border-t border-[#2A2D31] pt-4 flex items-center justify-between text-xs">
                  <span className="text-[#C8C4BA] uppercase tracking-wider">
                    Cache Latency Savings
                  </span>
                  <span className="text-[#2AC78A] font-semibold tabular-nums">
                    -{(selectedOff.p95_ms - selectedOn.p95_ms).toFixed(2)} ms (
                    {(
                      ((selectedOff.p95_ms - selectedOn.p95_ms) / selectedOff.p95_ms) *
                      100
                    ).toFixed(0)}
                    % faster)
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};
