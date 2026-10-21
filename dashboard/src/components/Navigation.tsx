import React from 'react';
import { PageId } from '../types';

interface Props {
  activePage: PageId;
  onSelectPage: (page: PageId) => void;
  isDark: boolean;
  onToggleTheme: () => void;
}

export const Navigation: React.FC<Props> = ({
  activePage,
  onSelectPage,
  isDark,
  onToggleTheme,
}) => {
  const pages: { id: PageId; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'simulator', label: 'Live Simulator' },
    { id: 'audit', label: 'Audit Log' },
    { id: 'policy-tester', label: 'Policy Tester' },
    { id: 'benchmarks', label: 'Benchmarks' },
    { id: 'about', label: 'About' },
  ];

  return (
    <header className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-900">
      {/* Top system status strip */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 px-4 py-1 text-xs font-mono text-neutral-600 dark:text-neutral-400 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="font-semibold tracking-wider text-neutral-900 dark:text-neutral-100">DOORMAN</span>
          <span className="text-neutral-400 dark:text-neutral-600">|</span>
          <span>ZERO-TRUST INGRESS PROXY</span>
          <span className="text-neutral-400 dark:text-neutral-600">|</span>
          <span className="text-status-allow dark:text-status-allow-dark">POLICY ENGINE: REST/OPA</span>
        </div>
        <div className="flex items-center gap-4">
          <span>PORT: 8080/443</span>
          <span className="text-neutral-400 dark:text-neutral-600">|</span>
          <span>MODE: FAIL_CLOSED</span>
        </div>
      </div>

      {/* Main navigation toolbar */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex flex-col">
            <span className="text-sm font-semibold tracking-tight text-neutral-900 dark:text-neutral-100">
              Security Operations Console
            </span>
            <span className="text-[11px] font-mono text-neutral-500 dark:text-neutral-400">
              v1.22.0 / SHA256-MTLS
            </span>
          </div>

          <nav className="flex items-center gap-1" aria-label="Main Navigation">
            {pages.map((p) => {
              const isActive = activePage === p.id;
              return (
                <button
                  key={p.id}
                  onClick={() => onSelectPage(p.id)}
                  className={`px-3 py-1 text-sm font-medium border ${
                    isActive
                      ? 'border-accent bg-accent text-white'
                      : 'border-transparent text-neutral-700 dark:text-neutral-300 hover:border-neutral-400 dark:hover:border-neutral-700 hover:text-neutral-900 dark:hover:text-neutral-100'
                  }`}
                >
                  {p.label}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onToggleTheme}
            className="px-2 py-1 text-xs font-mono border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 hover:border-neutral-400 dark:hover:border-neutral-600"
          >
            {isDark ? 'THEME: DARK' : 'THEME: LIGHT'}
          </button>
        </div>
      </div>
    </header>
  );
};
