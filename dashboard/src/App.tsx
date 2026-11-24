import React, { useEffect, useState } from 'react';
import { fetchInfraStatus } from './api';
import { TopIndexBar, NAV_SECTIONS } from './components/TopIndexBar';
import { HeroGate } from './components/HeroGate';
import { PipelineScrub } from './components/PipelineScrub';
import { LiveDispatcher } from './components/LiveDispatcher';
import { PolicyWorkbench } from './components/PolicyWorkbench';
import { BenchmarkPlot } from './components/BenchmarkPlot';
import { AuditLedger } from './components/AuditLedger';
import { CloudNativeInfra } from './components/CloudNativeInfra';

export const App: React.FC = () => {
  const [activeSection, setActiveSection] = useState<string>('gate');
  const [dockerRunning, setDockerRunning] = useState<boolean>(false);
  const [auditRefreshSignal, setAuditRefreshSignal] = useState<number>(0);

  // Check Docker stack health on boot
  useEffect(() => {
    fetchInfraStatus().then((status) => {
      setDockerRunning(status.dockerRunning);
    });
  }, []);

  // Track active section in viewport
  useEffect(() => {
    const elements = NAV_SECTIONS.map((s) => document.getElementById(s.id)).filter(
      (el): el is HTMLElement => Boolean(el)
    );
    if (elements.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible.length > 0) {
          setActiveSection(visible[0].target.id);
        }
      },
      { rootMargin: '-25% 0px -55% 0px', threshold: [0.1, 0.4] }
    );

    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const handleNavigate = (id: string) => {
    const target = document.getElementById(id);
    if (!target) return;
    setActiveSection(id);
    const top = target.getBoundingClientRect().top + window.scrollY - 56;
    window.scrollTo({ top, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen surface-bone bg-[#F4F3EE] text-[#141413] relative">
      <TopIndexBar
        activeSection={activeSection}
        dockerRunning={dockerRunning}
        onNavigate={handleNavigate}
      />

      <main>
        <HeroGate onNavigate={handleNavigate} />
        <PipelineScrub />
        <LiveDispatcher onRequestComplete={() => setAuditRefreshSignal((n) => n + 1)} />
        <PolicyWorkbench />
        <BenchmarkPlot />
        <AuditLedger refreshSignal={auditRefreshSignal} />
        <CloudNativeInfra />
      </main>

      <footer className="surface-carbon bg-[#0E0F10] text-[#F4F3EE] border-t border-[#2A2D31] px-6 sm:px-10 lg:px-12 py-8 font-mono text-[11px]">
        <div className="max-w-[1440px] mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-semibold tracking-[0.14em] uppercase text-[#F4F3EE]">
              Doorman
            </span>
            <span className="text-[#78756C]">/</span>
            <span className="text-[#C8C4BA]">
              Zero-Trust Identity-Aware Ingress Proxy · Go 1.22 · Keycloak · OPA · mTLS · Docker &amp; K8s
            </span>
          </div>
          <div className="text-[#C8C4BA]">
            FAIL-CLOSED AUTHZ · &lt; 12.00 MS P95 SLA · AUDIT SINK ACTIVE
          </div>
        </div>
      </footer>
    </div>
  );
};
