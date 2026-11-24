import React, { useState } from 'react';
import { Check, Copy, Play, ShieldAlert, ShieldCheck, Terminal } from 'lucide-react';
import { dispatchLiveRequest } from '../api';
import { SimulationResult } from '../types';

interface LiveDispatcherProps {
  onRequestComplete?: () => void;
}

interface PresetScenario {
  id: string;
  label: string;
  tag: string;
  user: string;
  posture: string;
  target: string;
  method: string;
  expectAllow: boolean;
}

const PRESETS: PresetScenario[] = [
  {
    id: 'alice-allow',
    label: 'Alice (Admin) + Compliant Posture',
    tag: '200 ALLOW',
    user: 'alice',
    posture: 'compliant',
    target: '/backend-a/',
    method: 'GET',
    expectAllow: true,
  },
  {
    id: 'bad-disk',
    label: 'Alice + Unencrypted Disk Posture',
    tag: '403 STEP 4',
    user: 'alice',
    posture: 'unhealthy_disk',
    target: '/backend-a/',
    method: 'GET',
    expectAllow: false,
  },
  {
    id: 'bob-admin',
    label: 'Bob (Viewer) -> /backend-a/admin',
    tag: '403 STEP 4',
    user: 'bob',
    posture: 'compliant',
    target: '/backend-a/admin',
    method: 'GET',
    expectAllow: false,
  },
  {
    id: 'anon-no-jwt',
    label: 'Anonymous (No Bearer JWT)',
    tag: '401 STEP 2',
    user: 'anonymous',
    posture: 'compliant',
    target: '/backend-a/',
    method: 'GET',
    expectAllow: false,
  },
  {
    id: 'missing-posture',
    label: 'Alice + Missing X-Device-Posture',
    tag: '403 STEP 3',
    user: 'alice',
    posture: 'missing',
    target: '/backend-b/',
    method: 'GET',
    expectAllow: false,
  },
];

export const LiveDispatcher: React.FC<LiveDispatcherProps> = ({ onRequestComplete }) => {
  const [user, setUser] = useState('alice');
  const [posture, setPosture] = useState('compliant');
  const [target, setTarget] = useState('/backend-a/');
  const [method, setMethod] = useState('GET');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [copied, setCopied] = useState(false);

  const runDispatch = async (params: {
    user: string;
    posture: string;
    target: string;
    method: string;
  }) => {
    setLoading(true);
    try {
      const res = await dispatchLiveRequest(params);
      setResult(res);
      onRequestComplete?.();
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (p: PresetScenario) => {
    setUser(p.user);
    setPosture(p.posture);
    setTarget(p.target);
    setMethod(p.method);
    runDispatch({ user: p.user, posture: p.posture, target: p.target, method: p.method });
  };

  const handleCopyCurl = async () => {
    if (!result?.curlCommand) return;
    try {
      await navigator.clipboard.writeText(result.curlCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard unavailable
    }
  };

  return (
    <section
      id="dispatch"
      className="surface-bone bg-[#F4F3EE] text-[#141413] border-b border-[#C9C5BA] py-20 lg:py-28"
    >
      <div className="max-w-[1440px] mx-auto px-6 sm:px-10 lg:px-12">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-10 border-b border-[#C9C5BA]">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#3D3C38] mb-3">
              03 / LIVE REQUEST DISPATCHER
            </div>
            <h2 className="font-serif text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] tracking-[-0.02em] text-[#141413]">
              Test the <em className="italic font-normal">Live</em> Proxy Stack.
            </h2>
          </div>
          <p className="max-w-md font-sans text-sm text-[#3D3C38] leading-relaxed">
            Mints a real Keycloak RS256 JWT and an ES256 posture token via{' '}
            <code className="text-[#141413] bg-[#EAE8E0] px-1">cmd/posture-agent</code>, then fires
            HTTPS traffic against Nginx and Doorman. Falls back cleanly to deterministic simulation
            if Docker containers are stopped.
          </p>
        </div>

        {/* Preset Strip */}
        <div className="py-6 border-b border-[#C9C5BA]">
          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-3">
            One-Click Demo Scenarios
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                disabled={loading}
                onClick={() => applyPreset(p)}
                className="text-left p-3.5 border border-[#C9C5BA] bg-[#EAE8E0]/80 hover:bg-[#EAE8E0] hover:border-[#141413] transition-colors flex flex-col justify-between gap-2 disabled:opacity-60"
              >
                <span
                  className={`inline-block self-start font-mono text-[10px] font-semibold px-1.5 py-0.5 ${
                    p.expectAllow
                      ? 'bg-[#1B7F5C]/15 text-[#1B7F5C] border border-[#1B7F5C]/40'
                      : 'bg-[#E63B2E]/10 text-[#C8281D] border border-[#E63B2E]/40'
                  }`}
                >
                  {p.tag}
                </span>
                <span className="font-sans text-xs font-medium text-[#141413] leading-snug">
                  {p.label}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Main 12-Col Console */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-8">
          {/* Controls (4 cols) */}
          <div className="lg:col-span-4 border border-[#C9C5BA] bg-[#EAE8E0] p-6 flex flex-col justify-between gap-6">
            <div className="space-y-5">
              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-2">
                  OIDC Identity (Keycloak)
                </label>
                <div className="grid grid-cols-3 border border-[#C9C5BA] divide-x divide-[#C9C5BA] bg-[#F4F3EE]">
                  {['alice', 'bob', 'anonymous'].map((u) => (
                    <button
                      key={u}
                      type="button"
                      onClick={() => setUser(u)}
                      className={`py-2 font-mono text-xs transition-colors ${
                        user === u
                          ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                          : 'text-[#3D3C38] hover:text-[#141413]'
                      }`}
                    >
                      {u}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-2">
                  Hardware Posture (ES256)
                </label>
                <div className="grid grid-cols-1 border border-[#C9C5BA] divide-y divide-[#C9C5BA] bg-[#F4F3EE]">
                  {[
                    { id: 'compliant', label: 'compliant (disk=true, fw=true, 5d)' },
                    { id: 'unhealthy_disk', label: 'unhealthy_disk (disk_encrypted=false)' },
                    { id: 'missing', label: 'missing (omit X-Device-Posture)' },
                  ].map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setPosture(opt.id)}
                      className={`px-3 py-2 text-left font-mono text-[11px] transition-colors ${
                        posture === opt.id
                          ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                          : 'text-[#3D3C38] hover:text-[#141413]'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label
                    htmlFor="dispatch-target"
                    className="block font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-2"
                  >
                    Target Route
                  </label>
                  <select
                    id="dispatch-target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="w-full px-3 py-2 border border-[#C9C5BA] bg-[#F4F3EE] font-mono text-xs text-[#141413]"
                  >
                    <option value="/backend-a/">/backend-a/</option>
                    <option value="/backend-b/">/backend-b/</option>
                    <option value="/backend-a/admin">/backend-a/admin</option>
                    <option value="/admin/config">/admin/config</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="dispatch-method"
                    className="block font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-2"
                  >
                    HTTP Method
                  </label>
                  <select
                    id="dispatch-method"
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="w-full px-3 py-2 border border-[#C9C5BA] bg-[#F4F3EE] font-mono text-xs text-[#141413]"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>
            </div>

            <button
              type="button"
              disabled={loading}
              onClick={() => runDispatch({ user, posture, target, method })}
              className="w-full py-3.5 px-5 bg-[#141413] text-[#F4F3EE] font-mono text-xs font-semibold uppercase tracking-[0.12em] hover:bg-[#1B7F5C] transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{loading ? 'Executing Pipeline...' : 'Dispatch Request'}</span>
            </button>
          </div>

          {/* Execution Trace (8 cols) */}
          <div className="lg:col-span-8 border border-[#2A2D31] surface-carbon bg-[#0E0F10] text-[#F4F3EE] p-6 flex flex-col justify-between gap-6">
            {!result ? (
              <div className="min-h-[340px] flex flex-col items-center justify-center text-center border border-dashed border-[#3A3D42] p-8">
                <Terminal className="w-8 h-8 text-[#C8C4BA] mb-3" />
                <div className="font-mono text-xs uppercase tracking-[0.14em] text-[#F4F3EE]">
                  Awaiting Request Dispatch
                </div>
                <p className="font-sans text-xs text-[#C8C4BA] max-w-sm mt-2">
                  Select any preset scenario above or configure custom headers and click Dispatch
                  Request to inspect live step-by-step execution.
                </p>
              </div>
            ) : (
              <>
                {/* Verdict Banner */}
                <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-[#2A2D31]">
                  <div className="flex items-center gap-3">
                    {result.decision === 'allow' ? (
                      <ShieldCheck className="w-6 h-6 text-[#2AC78A] shrink-0" />
                    ) : (
                      <ShieldAlert className="w-6 h-6 text-[#E63B2E] shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`font-mono text-lg font-semibold ${
                            result.decision === 'allow' ? 'text-[#2AC78A]' : 'text-[#FF6B5E]'
                          }`}
                        >
                          {result.statusText}
                        </span>
                        <span className="font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 border border-[#3A3D42] text-[#F4F3EE]">
                          {result.isLive ? 'LIVE PROXY' : 'LOCAL SIM'}
                        </span>
                      </div>
                      {result.reason && (
                        <div className="font-mono text-xs text-[#E2DFD7] mt-1">{result.reason}</div>
                      )}
                    </div>
                  </div>

                  <div className="font-mono text-right tabular-nums">
                    <div className="text-[10px] uppercase tracking-wider text-[#C8C4BA]">
                      Total Trace
                    </div>
                    <div className="text-lg font-semibold text-[#F4F3EE]">
                      {result.total_ms.toFixed(2)} ms
                    </div>
                  </div>
                </div>

                {/* 7-Step Trace Grid */}
                <div className="divide-y divide-[#2A2D31] border border-[#2A2D31]">
                  {result.steps.map((st) => {
                    const badgeStyle =
                      st.status === 'pass'
                        ? 'text-[#2AC78A] border-[#1B7F5C]/60 bg-[#122E24]'
                        : st.status === 'fail'
                          ? 'text-[#FF6B5E] border-[#E63B2E]/60 bg-[#3B1614]'
                          : 'text-[#C8C4BA] border-[#2A2D31] bg-[#161719]';
                    return (
                      <div
                        key={st.step}
                        className="px-4 py-2.5 flex items-start justify-between gap-4 text-xs"
                      >
                        <div className="flex items-start gap-3">
                          <span className="font-mono text-[#A3A097] tabular-nums pt-0.5">
                            0{st.step}
                          </span>
                          <div>
                            <div className="font-mono font-medium text-[#F4F3EE]">
                              {st.name}{' '}
                              <span className="text-[#C8C4BA] font-normal">({st.subsystem})</span>
                            </div>
                            <div className="font-sans text-[#C8C4BA] mt-0.5">{st.details}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 shrink-0 font-mono">
                          <span className="tabular-nums text-[#E2DFD7]">
                            {st.latency_ms.toFixed(2)}ms
                          </span>
                          <span className={`px-1.5 py-0.5 text-[10px] uppercase border ${badgeStyle}`}>
                            {st.status}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* cURL + Response Body */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border border-[#2A2D31] bg-[#161719] p-3.5">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-[10px] uppercase tracking-wider text-[#C8C4BA]">
                        Equivalent cURL Command
                      </span>
                      <button
                        type="button"
                        onClick={handleCopyCurl}
                        className="inline-flex items-center gap-1 font-mono text-[10px] text-[#F4F3EE] hover:text-[#2AC78A]"
                      >
                        {copied ? (
                          <Check className="w-3 h-3 text-[#2AC78A]" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                        <span>{copied ? 'COPIED' : 'COPY'}</span>
                      </button>
                    </div>
                    <pre className="font-mono text-[11px] text-[#E2DFD7] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                      {result.curlCommand}
                    </pre>
                  </div>

                  <div className="border border-[#2A2D31] bg-[#161719] p-3.5">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[#C8C4BA] mb-2">
                      Upstream / Proxy Response
                    </div>
                    <pre className="font-mono text-[11px] text-[#2AC78A] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                      {result.responseBody || '(empty body)'}
                    </pre>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};
