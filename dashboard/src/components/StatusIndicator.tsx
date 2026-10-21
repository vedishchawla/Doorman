import React from 'react';

interface Props {
  decision: 'allow' | 'deny' | 'warning' | string;
  size?: 'sm' | 'md';
}

export const StatusIndicator: React.FC<Props> = ({ decision, size = 'sm' }) => {
  const norm = decision.toLowerCase();
  const isAllow = norm === 'allow' || norm === 'allowed' || norm === 'true' || norm === 'pass';
  const isDeny = norm === 'deny' || norm === 'denied' || norm === 'false' || norm === 'fail';

  const textSize = size === 'sm' ? 'text-xs' : 'text-sm';
  const iconSize = size === 'sm' ? 'w-3 h-3' : 'w-4 h-4';

  if (isAllow) {
    return (
      <span className={`inline-flex items-center gap-1 font-mono font-medium ${textSize} text-status-allow dark:text-status-allow-dark`}>
        <svg className={iconSize} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z" />
        </svg>
        <span>ALLOW</span>
      </span>
    );
  }

  if (isDeny) {
    return (
      <span className={`inline-flex items-center gap-1 font-mono font-medium ${textSize} text-status-deny dark:text-status-deny-dark`}>
        <svg className={iconSize} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M3.72 3.72a.75.75 0 011.06 0L8 6.94l3.22-3.22a.75.75 0 111.06 1.06L9.06 8l3.22 3.22a.75.75 0 11-1.06 1.06L8 9.06l-3.22 3.22a.75.75 0 01-1.06-1.06L6.94 8 3.72 4.78a.75.75 0 010-1.06z" />
        </svg>
        <span>DENY</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1 font-mono font-medium ${textSize} text-status-warn dark:text-status-warn-dark`}>
      <svg className={iconSize} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM8 5a.75.75 0 00-.75.75v3.5a.75.75 0 001.5 0v-3.5A.75.75 0 008 5zm0 8a1 1 0 100-2 1 1 0 000 2z" />
      </svg>
      <span>{decision.toUpperCase()}</span>
    </span>
  );
};
