import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { evaluatePolicy, fetchRegoSource } from '../api';
import { PolicyEvaluationResult, PolicyInput } from '../types';

const COUNTRIES = ['IN', 'US', 'GB', 'DE', 'CA', 'RU', 'CN'];
const RESOURCES = ['/backend-a/data', '/backend-b/reports', '/admin/config'];
const METHODS = ['GET', 'POST', 'DELETE'];

export const PolicyWorkbench: React.FC = () => {
  const verdictRef = useRef<HTMLDivElement>(null);

  const [input, setInput] = useState<PolicyInput>({
    user: 'alice',
    roles: ['admin'],
    resource: '/backend-a/data',
    method: 'GET',
    ip: '172.18.0.7',
    geo: 'IN',
    time: '14:00',
    device_posture: {
      disk_encrypted: true,
      firewall_on: true,
      os_patch_age_days: 5,
    },
  });

  const [result, setResult] = useState<PolicyEvaluationResult>({
    allow: true,
    policy_id: '',
    reason: '',
    denials: [],
  });

  const [regoSource, setRegoSource] = useState<string>('');

  useEffect(() => {
    fetchRegoSource().then(setRegoSource);
  }, []);

  useEffect(() => {
    let active = true;
    evaluatePolicy(input).then((res) => {
      if (!active) return;
      setResult(res);
      if (verdictRef.current) {
        gsap.fromTo(
          verdictRef.current,
          { scale: 0.985, opacity: 0.8 },
          { scale: 1, opacity: 1, duration: 0.3, ease: 'expo.out' }
        );
      }
    });
    return () => {
      active = false;
    };
  }, [input]);

  const activeRuleIds = new Set((result.denials || []).map((d) => d.rule_id));
  const hourValue = parseInt(input.time.split(':')[0], 10) || 0;
  const regoLines = regoSource.split('\n');

  const isLineHighlighted = (lineIdx: number): 'deny' | 'allow' | null => {
    const line = regoLines[lineIdx] || '';
    for (const ruleId of activeRuleIds) {
      if (line.includes(`"${ruleId}"`)) return 'deny';
    }
    if (result.allow && (line.startsWith('allow if') || line.includes('count(denials) == 0'))) {
      return 'allow';
    }
    return null;
  };

  return (
    <section
      id="policy"
      className="surface-carbon bg-[#0E0F10] text-[#F4F3EE] border-b border-[#2A2D31] arch-grid-carbon py-20 lg:py-28"
    >
      <div className="max-w-[1440px] mx-auto px-6 sm:px-10 lg:px-12">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-10 border-b border-[#2A2D31]">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#C8C4BA] mb-3">
              04 / DECLARATIVE OPA REGO WORKBENCH
            </div>
            <h2 className="font-serif text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] tracking-[-0.02em] text-[#F4F3EE]">
              Context-Aware <em className="italic font-normal text-[#FF6B5E]">Fail-Closed</em> Policy.
            </h2>
          </div>
          <p className="max-w-md font-sans text-sm text-[#C8C4BA] leading-relaxed">
            Toggle hardware posture, role, time-of-day, or geo origin below. Every change runs live
            against <code className="text-[#F4F3EE] bg-[#161719] px-1">policies/authz.rego</code>{' '}
            and highlights the exact rule firing.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-10">
          {/* Left: Tactile Hardware Controls (5 cols) */}
          <div className="lg:col-span-5 border border-[#2A2D31] bg-[#161719] p-6 space-y-6">
            {/* Hardware Posture Toggles */}
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#C8C4BA] mb-3">
                ES256 Hardware Posture Signals
              </div>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() =>
                    setInput((p) => ({
                      ...p,
                      device_posture: {
                        ...p.device_posture,
                        disk_encrypted: !p.device_posture.disk_encrypted,
                      },
                    }))
                  }
                  className={`p-3.5 border text-left transition-colors ${
                    input.device_posture.disk_encrypted
                      ? 'border-[#1B7F5C] bg-[#122E24] text-[#F4F3EE]'
                      : 'border-[#E63B2E] bg-[#3B1614] text-[#F4F3EE]'
                  }`}
                >
                  <div className="font-mono text-[10px] uppercase tracking-wider text-[#C8C4BA]">
                    Disk Encryption
                  </div>
                  <div
                    className={`font-mono text-sm font-semibold mt-1 ${
                      input.device_posture.disk_encrypted ? 'text-[#2AC78A]' : 'text-[#FF6B5E]'
                    }`}
                  >
                    {input.device_posture.disk_encrypted ? 'ENCRYPTED' : 'UNENCRYPTED'}
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() =>
                    setInput((p) => ({
                      ...p,
                      device_posture: {
                        ...p.device_posture,
                        firewall_on: !p.device_posture.firewall_on,
                      },
                    }))
                  }
                  className={`p-3.5 border text-left transition-colors ${
                    input.device_posture.firewall_on
                      ? 'border-[#1B7F5C] bg-[#122E24] text-[#F4F3EE]'
                      : 'border-[#E63B2E] bg-[#3B1614] text-[#F4F3EE]'
                  }`}
                >
                  <div className="font-mono text-[10px] uppercase tracking-wider text-[#C8C4BA]">
                    Host Firewall
                  </div>
                  <div
                    className={`font-mono text-sm font-semibold mt-1 ${
                      input.device_posture.firewall_on ? 'text-[#2AC78A]' : 'text-[#FF6B5E]'
                    }`}
                  >
                    {input.device_posture.firewall_on ? 'ENABLED' : 'DISABLED'}
                  </div>
                </button>
              </div>
            </div>

            {/* OS Patch Age Slider */}
            <div>
              <div className="flex items-center justify-between font-mono text-xs mb-2">
                <span className="text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA]">
                  OS Patch Age (Limit &le; 30d)
                </span>
                <span
                  className={`tabular-nums font-semibold ${
                    input.device_posture.os_patch_age_days > 30
                      ? 'text-[#FF6B5E]'
                      : 'text-[#2AC78A]'
                  }`}
                >
                  {input.device_posture.os_patch_age_days} days
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={60}
                value={input.device_posture.os_patch_age_days}
                onChange={(e) =>
                  setInput((p) => ({
                    ...p,
                    device_posture: {
                      ...p.device_posture,
                      os_patch_age_days: Number(e.target.value),
                    },
                  }))
                }
                className="w-full accent-[#2AC78A] cursor-pointer"
              />
              <div className="flex justify-between font-mono text-[10px] text-[#C8C4BA] mt-1 tabular-nums">
                <span>0d</span>
                <span className="text-[#F59E0B]">30d SLA CUTOFF</span>
                <span>60d</span>
              </div>
            </div>

            {/* Role Selector */}
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA] mb-2">
                OIDC Role Claim
              </div>
              <div className="grid grid-cols-3 border border-[#2A2D31] divide-x divide-[#2A2D31] bg-[#0E0F10]">
                {['admin', 'viewer', 'guest'].map((role) => {
                  const active = input.roles[0] === role;
                  return (
                    <button
                      key={role}
                      type="button"
                      onClick={() =>
                        setInput((p) => ({
                          ...p,
                          user: role === 'admin' ? 'alice' : role === 'viewer' ? 'bob' : 'unknown',
                          roles: [role],
                        }))
                      }
                      className={`py-2 font-mono text-xs transition-colors ${
                        active
                          ? 'bg-[#F4F3EE] text-[#0E0F10] font-semibold'
                          : 'text-[#C8C4BA] hover:text-[#F4F3EE]'
                      }`}
                    >
                      {role}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Method + Resource */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA] mb-2">
                  HTTP Method
                </div>
                <div className="grid grid-cols-3 border border-[#2A2D31] divide-x divide-[#2A2D31] bg-[#0E0F10]">
                  {METHODS.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setInput((p) => ({ ...p, method: m }))}
                      className={`py-2 font-mono text-[11px] transition-colors ${
                        input.method === m
                          ? 'bg-[#F4F3EE] text-[#0E0F10] font-semibold'
                          : 'text-[#C8C4BA] hover:text-[#F4F3EE]'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label
                  htmlFor="policy-resource"
                  className="block font-mono text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA] mb-2"
                >
                  Resource Path
                </label>
                <select
                  id="policy-resource"
                  value={input.resource}
                  onChange={(e) => setInput((p) => ({ ...p, resource: e.target.value }))}
                  className="w-full px-3 py-2 border border-[#2A2D31] bg-[#0E0F10] font-mono text-xs text-[#F4F3EE]"
                >
                  {RESOURCES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Country + Hour */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA] mb-2">
                  Origin Country (Geo)
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {COUNTRIES.map((c) => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setInput((p) => ({ ...p, geo: c }))}
                      className={`px-2.5 py-1.5 font-mono text-[11px] border transition-colors ${
                        input.geo === c
                          ? 'bg-[#F4F3EE] text-[#0E0F10] border-[#F4F3EE] font-semibold'
                          : 'bg-[#0E0F10] text-[#C8C4BA] border-[#2A2D31] hover:text-[#F4F3EE]'
                      }`}
                    >
                      {c}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.14em] text-[#C8C4BA] mb-2">
                  <span>Request Hour</span>
                  <span className="text-[#F4F3EE] tabular-nums">{input.time}</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={23}
                  value={hourValue}
                  onChange={(e) => {
                    const hh = String(e.target.value).padStart(2, '0');
                    setInput((p) => ({ ...p, time: `${hh}:00` }));
                  }}
                  className="w-full accent-[#2AC78A] cursor-pointer"
                />
                <div className="font-mono text-[10px] text-[#C8C4BA] mt-1">
                  Viewer window: 09:00 – 19:00
                </div>
              </div>
            </div>
          </div>

          {/* Right: Verdict Stamp + Live authz.rego Source (7 cols) */}
          <div className="lg:col-span-7 flex flex-col gap-6">
            {/* Typographic Verdict Stamp */}
            <div
              ref={verdictRef}
              className={`border p-6 transition-colors ${
                result.allow
                  ? 'border-[#1B7F5C] bg-[#122E24]'
                  : 'border-[#E63B2E] bg-[#3B1614]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#E2DFD7] mb-1">
                    OPA Evaluation Output (zt.authz)
                  </div>
                  <div
                    className={`font-mono text-2xl sm:text-3xl font-semibold tracking-tight ${
                      result.allow ? 'text-[#2AC78A]' : 'text-[#FF6B5E]'
                    }`}
                  >
                    {result.allow
                      ? 'ALLOW — 0 DENIALS'
                      : `403 FORBIDDEN — ${result.policy_id || 'denied'}`}
                  </div>
                </div>
                <div className="font-mono text-xs tabular-nums px-3 py-1.5 border border-[#2A2D31] bg-[#0E0F10] text-[#F4F3EE]">
                  DENIALS: {(result.denials || []).length}
                </div>
              </div>

              {!result.allow && result.denials && result.denials.length > 0 && (
                <ul className="mt-4 pt-4 border-t border-[#E63B2E]/40 space-y-1.5 font-mono text-xs text-[#F4F3EE]">
                  {result.denials.map((d) => (
                    <li key={d.rule_id} className="flex items-start gap-2">
                      <span className="text-[#FF6B5E] shrink-0">[{d.rule_id}]</span>
                      <span>{d.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Live policies/authz.rego Source Viewer */}
            <div className="border border-[#2A2D31] bg-[#161719] flex-1 flex flex-col overflow-hidden">
              <div className="px-4 py-3 border-b border-[#2A2D31] flex items-center justify-between font-mono text-[11px] bg-[#0E0F10]">
                <span className="text-[#F4F3EE] font-semibold">policies/authz.rego</span>
                <span className="text-[#C8C4BA]">LIVE REGO SOURCE</span>
              </div>
              <div className="p-4 overflow-auto max-h-[380px] font-mono text-[11px] leading-relaxed bg-[#0E0F10]">
                {regoLines.map((line, i) => {
                  const highlight = isLineHighlighted(i);
                  const rowCls =
                    highlight === 'deny'
                      ? 'bg-[#3B1614] text-[#FF6B5E] border-l-2 border-[#E63B2E] pl-2 font-medium'
                      : highlight === 'allow'
                        ? 'bg-[#122E24] text-[#2AC78A] border-l-2 border-[#2AC78A] pl-2 font-medium'
                        : 'text-[#E2DFD7] pl-2.5';
                  return (
                    <div key={i} className={`flex gap-4 py-0.5 ${rowCls}`}>
                      <span className="w-6 text-right text-[#78756C] select-none tabular-nums shrink-0">
                        {i + 1}
                      </span>
                      <span className="whitespace-pre">{line}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
