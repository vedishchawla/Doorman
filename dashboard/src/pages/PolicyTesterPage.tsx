import React, { useState } from 'react';
import { PolicyInput, PolicyEvaluationResult } from '../types';
import { evaluatePolicy } from '../api';
import { StatusIndicator } from '../components/StatusIndicator';

interface Preset {
  id: string;
  name: string;
  expected: 'allow' | 'deny';
  input: PolicyInput;
}

const PRESETS: Preset[] = [
  {
    id: 'admin-allow',
    name: 'Admin standard grant (all paths, all methods)',
    expected: 'allow',
    input: {
      user: 'alice',
      roles: ['admin', 'default-roles-zt'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'sec-ops-mac-01',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 5,
      },
    },
  },
  {
    id: 'viewer-allow',
    name: 'Viewer standard grant (business hours, GET, non-admin)',
    expected: 'allow',
    input: {
      user: 'bob',
      roles: ['viewer', 'default-roles-zt'],
      resource: '/backend-b/reports',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '11:00',
      device_posture: {
        device_id: 'sec-ops-mac-02',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 12,
      },
    },
  },
  {
    id: 'viewer-admin-deny',
    name: 'Viewer denied: /admin path prohibited',
    expected: 'deny',
    input: {
      user: 'bob',
      roles: ['viewer', 'default-roles-zt'],
      resource: '/admin/config',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'sec-ops-mac-02',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 12,
      },
    },
  },
  {
    id: 'viewer-hours-deny',
    name: 'Viewer denied: outside business hours (21:00)',
    expected: 'deny',
    input: {
      user: 'bob',
      roles: ['viewer', 'default-roles-zt'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '21:00',
      device_posture: {
        device_id: 'sec-ops-mac-02',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 12,
      },
    },
  },
  {
    id: 'viewer-post-deny',
    name: 'Viewer denied: mutating method (POST)',
    expected: 'deny',
    input: {
      user: 'bob',
      roles: ['viewer', 'default-roles-zt'],
      resource: '/backend-a/data',
      method: 'POST',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'sec-ops-mac-02',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 12,
      },
    },
  },
  {
    id: 'geo-blocked-deny',
    name: 'Geo-blocking denied: country not in allowlist (RU)',
    expected: 'deny',
    input: {
      user: 'alice',
      roles: ['admin'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '198.51.100.22',
      geo: 'RU',
      time: '14:00',
      device_posture: {
        device_id: 'sec-ops-mac-01',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 5,
      },
    },
  },
  {
    id: 'posture-disk-deny',
    name: 'Device posture denied: disk not encrypted',
    expected: 'deny',
    input: {
      user: 'alice',
      roles: ['admin'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'untrusted-host',
        disk_encrypted: false,
        firewall_on: true,
        os_patch_age_days: 5,
      },
    },
  },
  {
    id: 'posture-firewall-deny',
    name: 'Device posture denied: firewall disabled',
    expected: 'deny',
    input: {
      user: 'alice',
      roles: ['admin'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'untrusted-host',
        disk_encrypted: true,
        firewall_on: false,
        os_patch_age_days: 5,
      },
    },
  },
  {
    id: 'posture-patch-deny',
    name: 'Device posture denied: OS patch age exceeds 30 days (45 days)',
    expected: 'deny',
    input: {
      user: 'alice',
      roles: ['admin'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'stale-laptop',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 45,
      },
    },
  },
  {
    id: 'unknown-role-deny',
    name: 'Unknown role denied: user lacks admin or viewer',
    expected: 'deny',
    input: {
      user: 'contractor',
      roles: ['contractor-read'],
      resource: '/backend-a/data',
      method: 'GET',
      ip: '172.18.0.7',
      geo: 'IN',
      time: '14:00',
      device_posture: {
        device_id: 'sec-ops-mac-01',
        disk_encrypted: true,
        firewall_on: true,
        os_patch_age_days: 5,
      },
    },
  },
];

export const PolicyTesterPage: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<string>(PRESETS[0].id);
  const [jsonInput, setJsonInput] = useState<string>(
    JSON.stringify(PRESETS[0].input, null, 2)
  );
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [result, setResult] = useState<PolicyEvaluationResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);

  // Evaluate on load
  React.useEffect(() => {
    try {
      const parsed = JSON.parse(jsonInput);
      evaluatePolicy(parsed).then(setResult);
    } catch (err) {}
  }, []);

  const handlePresetChange = (presetId: string) => {
    setSelectedPreset(presetId);
    const p = PRESETS.find((x) => x.id === presetId);
    if (p) {
      const text = JSON.stringify(p.input, null, 2);
      setJsonInput(text);
      setJsonError(null);
      evaluatePolicy(p.input).then(setResult);
    }
  };

  const handleJsonChange = (val: string) => {
    setJsonInput(val);
    try {
      JSON.parse(val);
      setJsonError(null);
    } catch (err: any) {
      setJsonError(err.message);
    }
  };

  const handleEvaluate = async () => {
    try {
      const parsed = JSON.parse(jsonInput);
      setJsonError(null);
      setIsEvaluating(true);
      const res = await evaluatePolicy(parsed);
      setResult(res);
      setIsEvaluating(false);
    } catch (err: any) {
      setJsonError(`Invalid JSON: ${err.message}`);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <div>
          <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100 uppercase tracking-wide">
            OPA Policy Evaluation Tester
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono mt-1">
            Test policy inputs against zt.authz rules and inspect deterministic decisions and denial sets
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-neutral-500">ENGINE: zt.authz / REST</span>
        </div>
      </div>

      {/* Preset selector bar */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-3 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div className="flex-1 w-full">
          <label className="block text-[11px] font-mono text-neutral-600 dark:text-neutral-400 uppercase mb-1">
            Select Test Fixture / Preset Scenario
          </label>
          <select
            value={selectedPreset}
            onChange={(e) => handlePresetChange(e.target.value)}
            className="w-full text-xs font-mono px-2 py-1.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 rounded-none"
          >
            {PRESETS.map((p) => (
              <option key={p.id} value={p.id}>
                [{p.expected.toUpperCase()}] {p.name}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-end gap-2 w-full md:w-auto">
          <button
            onClick={handleEvaluate}
            disabled={isEvaluating}
            className="w-full md:w-auto px-4 py-1.5 text-xs font-mono font-medium border border-accent bg-accent text-white hover:bg-accent-hover"
          >
            {isEvaluating ? 'EVALUATING...' : 'EVALUATE POLICY'}
          </button>
        </div>
      </div>

      {/* Main split view: Editor on Left, Output on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Input JSON Editor */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 flex flex-col">
          <div className="border-b border-neutral-300 dark:border-neutral-800 px-3 py-2 bg-neutral-100 dark:bg-neutral-800/60 flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-neutral-900 dark:text-neutral-100">
              INPUT JSON DOCUMENT (input)
            </span>
            {jsonError ? (
              <span className="text-[11px] font-mono text-status-deny dark:text-status-deny-dark">
                SYNTAX ERROR
              </span>
            ) : (
              <span className="text-[11px] font-mono text-status-allow dark:text-status-allow-dark">
                VALID JSON
              </span>
            )}
          </div>
          <div className="p-2 flex-1 flex flex-col">
            <textarea
              value={jsonInput}
              onChange={(e) => handleJsonChange(e.target.value)}
              rows={18}
              spellCheck={false}
              className="w-full flex-1 text-xs font-mono p-2 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 rounded-none resize-y leading-relaxed"
            />
            {jsonError && (
              <div className="mt-2 p-2 text-xs font-mono text-status-deny dark:text-status-deny-dark bg-neutral-100 dark:bg-neutral-950 border border-neutral-300 dark:border-neutral-800">
                {jsonError}
              </div>
            )}
          </div>
        </div>

        {/* Right: Decision and Reasoning Display */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-neutral-900 flex flex-col">
          <div className="border-b border-neutral-300 dark:border-neutral-800 px-3 py-2 bg-neutral-100 dark:bg-neutral-800/60 flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-neutral-900 dark:text-neutral-100">
              EVALUATION RESULT
            </span>
            {result && <StatusIndicator decision={result.allow ? 'allow' : 'deny'} size="md" />}
          </div>

          <div className="p-4 space-y-4 flex-1">
            {result ? (
              <>
                {/* Decision summary box */}
                <div className="border border-neutral-300 dark:border-neutral-800 p-3 space-y-2 bg-neutral-50 dark:bg-neutral-950">
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div>
                      <span className="text-neutral-500 block text-[10px]">DECISION RESULT</span>
                      <span
                        className={`font-semibold ${
                          result.allow
                            ? 'text-status-allow dark:text-status-allow-dark'
                            : 'text-status-deny dark:text-status-deny-dark'
                        }`}
                      >
                        {result.allow ? 'TRUE (ACCESS GRANTED)' : 'FALSE (ACCESS DENIED)'}
                      </span>
                    </div>
                    <div>
                      <span className="text-neutral-500 block text-[10px]">POLICY ID</span>
                      <span className="text-neutral-900 dark:text-neutral-100">
                        {result.policy_id || '(none)'}
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="text-neutral-500 block text-[10px] font-mono">PRIMARY REASON</span>
                    <div className="text-xs font-mono text-neutral-900 dark:text-neutral-100 font-medium mt-0.5">
                      {result.reason || 'Allow if no denials and user has a recognized role grant'}
                    </div>
                  </div>
                </div>

                {/* Triggered Denials Table */}
                <div>
                  <div className="text-xs font-mono font-medium text-neutral-900 dark:text-neutral-100 mb-1 flex items-center justify-between">
                    <span>DENIAL SET (denials)</span>
                    <span className="text-neutral-500 text-[11px]">
                      {result.denials?.length || 0} TRIGGERED
                    </span>
                  </div>

                  {!result.denials || result.denials.length === 0 ? (
                    <div className="p-3 border border-neutral-300 dark:border-neutral-800 text-xs font-mono text-neutral-500 bg-neutral-50 dark:bg-neutral-950">
                      Empty denial set. Positive grant active.
                    </div>
                  ) : (
                    <div className="border border-neutral-300 dark:border-neutral-800 overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs font-mono">
                        <thead>
                          <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-800/70 text-neutral-600 dark:text-neutral-400">
                            <th className="py-1.5 px-3 font-medium">RULE ID</th>
                            <th className="py-1.5 px-3 font-medium">MESSAGE</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                          {result.denials.map((d, i) => (
                            <tr key={i} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
                              <td className="py-1.5 px-3 text-status-deny dark:text-status-deny-dark font-medium whitespace-nowrap">
                                {d.rule_id}
                              </td>
                              <td className="py-1.5 px-3 text-neutral-800 dark:text-neutral-200">
                                {d.message}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Raw JSON result */}
                <div>
                  <span className="text-[10px] font-mono text-neutral-500 block mb-1">
                    RAW OPA RESPONSE PAYLOAD
                  </span>
                  <pre className="p-2 border border-neutral-200 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-950 text-[11px] font-mono text-neutral-700 dark:text-neutral-300 overflow-x-auto max-h-[160px]">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              </>
            ) : (
              <div className="p-4 text-xs font-mono text-neutral-500">
                Click Evaluate Policy to inspect output.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
