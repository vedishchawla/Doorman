import React from 'react';

export interface NavSection {
  id: string;
  index: string;
  label: string;
}

export const NAV_SECTIONS: NavSection[] = [
  { id: 'gate', index: '01', label: 'GATE' },
  { id: 'pipeline', index: '02', label: 'PIPELINE' },
  { id: 'dispatch', index: '03', label: 'DISPATCH' },
  { id: 'policy', index: '04', label: 'POLICY' },
  { id: 'bench', index: '05', label: 'BENCH' },
  { id: 'audit', index: '06', label: 'AUDIT' },
  { id: 'cloud', index: '07', label: 'CLOUD' },
];

interface TopIndexBarProps {
  activeSection: string;
  dockerRunning: boolean;
  onNavigate: (id: string) => void;
}

export const TopIndexBar: React.FC<TopIndexBarProps> = ({
  activeSection,
  dockerRunning,
  onNavigate,
}) => {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 h-14 bg-[#F4F3EE] border-b border-[#C9C5BA] text-[#141413]">
      <div className="max-w-[1440px] mx-auto h-full px-4 sm:px-8 flex items-center justify-between gap-4">
        {/* Brand */}
        <button
          type="button"
          onClick={() => onNavigate('gate')}
          className="flex items-center gap-3 text-left group focus-visible:outline-[#141413]"
        >
          <span className="inline-flex h-6 w-6 items-center justify-center bg-[#141413] text-[#F4F3EE] font-mono text-xs font-semibold tracking-tight">
            DM
          </span>
          <div className="flex items-baseline gap-2.5">
            <span className="font-mono text-xs font-semibold tracking-[0.14em] uppercase text-[#141413]">
              Doorman
            </span>
            <span className="hidden lg:inline font-mono text-[11px] text-[#3D3C38] tracking-wider">
              ZT-INGRESS / GO 1.22
            </span>
          </div>
        </button>

        {/* Numbered Swiss Index Navigation */}
        <nav aria-label="Primary sections" className="hidden md:flex items-center h-full">
          {NAV_SECTIONS.map((sec) => {
            const isActive = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => onNavigate(sec.id)}
                className={`relative h-full px-3 lg:px-4 flex items-center gap-1.5 font-mono text-[11px] tracking-[0.08em] transition-colors duration-200 ${
                  isActive ? 'text-[#141413] font-semibold' : 'text-[#4A4944] hover:text-[#141413]'
                }`}
              >
                <span className="tabular-nums opacity-70">{sec.index}</span>
                <span>{sec.label}</span>
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute bottom-0 left-2 right-2 h-[2px] bg-[#141413]"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Telemetry Status + p95 Readout */}
        <div className="flex items-center gap-4 font-mono text-[11px] tabular-nums">
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 border border-[#C9C5BA] bg-[#EAE8E0]">
            <span className="text-[#3D3C38]">p95</span>
            <span className="font-semibold text-[#1B7F5C]">7.34 ms</span>
            <span className="text-[#3D3C38]">/ 12.00</span>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('cloud')}
            className="flex items-center gap-2 px-2.5 py-1 border border-[#C9C5BA] hover:border-[#141413] transition-colors"
            title={dockerRunning ? 'Docker Compose stack active' : 'Standalone console mode'}
          >
            <span className="relative flex h-2 w-2">
              {dockerRunning && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#1B7F5C] opacity-75" />
              )}
              <span
                className={`relative inline-flex h-2 w-2 rounded-full ${
                  dockerRunning ? 'bg-[#1B7F5C]' : 'bg-[#D97706]'
                }`}
              />
            </span>
            <span className="tracking-wider uppercase text-[#141413] font-medium">
              {dockerRunning ? 'STACK LIVE' : 'STANDBY'}
            </span>
          </button>
        </div>
      </div>
    </header>
  );
};
