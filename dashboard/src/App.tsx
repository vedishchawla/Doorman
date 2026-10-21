import React, { useState, useEffect } from 'react';
import { PageId } from './types';
import { Navigation } from './components/Navigation';
import { OverviewPage } from './pages/OverviewPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { PolicyTesterPage } from './pages/PolicyTesterPage';
import { BenchmarksPage } from './pages/BenchmarksPage';
import { AboutPage } from './pages/AboutPage';

export const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('overview');
  const [isDark, setIsDark] = useState<boolean>(true);

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.classList.add('light');
    }
  }, [isDark]);

  const toggleTheme = () => {
    setIsDark(!isDark);
  };

  return (
    <div className="min-h-screen bg-neutral-100 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 flex flex-col font-sans">
      <Navigation
        activePage={activePage}
        onSelectPage={setActivePage}
        isDark={isDark}
        onToggleTheme={toggleTheme}
      />

      <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
        {activePage === 'overview' && <OverviewPage />}
        {activePage === 'audit' && <AuditLogPage />}
        {activePage === 'policy-tester' && <PolicyTesterPage />}
        {activePage === 'benchmarks' && <BenchmarksPage />}
        {activePage === 'about' && <AboutPage />}
      </main>

      <footer className="border-t border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-900 px-6 py-3 text-xs font-mono text-neutral-500 dark:text-neutral-400">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-2">
          <div>
            <span>DOORMAN ZERO-TRUST INGRESS PROXY</span>
            <span className="mx-2 text-neutral-400 dark:text-neutral-600">|</span>
            <span>GO 1.22 / KEYCLOAK / OPA / MTLS</span>
          </div>
          <div>
            <span>FAIL-CLOSED AUTHZ ENGINE</span>
            <span className="mx-2 text-neutral-400 dark:text-neutral-600">|</span>
            <span>AUDIT LOG SINK ACTIVE</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
