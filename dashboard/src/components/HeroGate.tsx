import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { ArrowDownRight, Pause, Play, Plus } from 'lucide-react';

interface HeroGateProps {
  onNavigate: (id: string) => void;
}

interface Packet {
  x: number;
  y: number;
  targetY: number;
  vx: number;
  allow: boolean;
  decided: boolean;
  latency: number;
  user: string;
}

export const HeroGate: React.FC<HeroGateProps> = ({ onNavigate }) => {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const packetsRef = useRef<Packet[]>([]);
  const pausedRef = useRef(false);
  const isVisibleRef = useRef(true);

  const [paused, setPaused] = useState(false);
  const [liveStats, setLiveStats] = useState({
    p95: 7.34,
    allowed: 142,
    denied: 29,
  });

  // GSAP entrance animation
  useEffect(() => {
    const ctx = gsap.context(() => {
      const mm = gsap.matchMedia();
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        gsap.from('.hero-line-inner', {
          yPercent: 110,
          duration: 0.9,
          stagger: 0.08,
          ease: 'expo.out',
          clearProps: 'transform',
        });
        gsap.from('.hero-hairline', {
          scaleX: 0,
          transformOrigin: 'left center',
          duration: 0.85,
          stagger: 0.07,
          ease: 'expo.out',
        });
        gsap.from('.hero-fade', {
          opacity: 0,
          y: 14,
          duration: 0.75,
          stagger: 0.06,
          delay: 0.2,
          ease: 'expo.out',
        });
      });
    }, rootRef);

    return () => ctx.revert();
  }, []);

  // Pause canvas RAF loop automatically when off-screen for zero scroll jitter
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        isVisibleRef.current = entry.isIntersecting;
      },
      { threshold: 0.02 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  // Canvas Packet Gate Oscilloscope
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let rafId = 0;
    let width = 0;
    let height = 0;
    let lastSpawn = 0;
    let lastStatTick = 0;

    const spawnPacket = (forceDeny?: boolean) => {
      const allow = forceDeny !== undefined ? !forceDeny : Math.random() > 0.22;
      const laneOffsets = [-44, -22, 0, 22, 44];
      const offset = laneOffsets[Math.floor(Math.random() * laneOffsets.length)];
      packetsRef.current.push({
        x: 16,
        y: height * 0.5 + offset * 0.45,
        targetY: allow ? height * 0.28 : height * 0.72,
        vx: 2.3 + Math.random() * 1.4,
        allow,
        decided: false,
        latency: allow ? 5.9 + Math.random() * 4.4 : 1.1 + Math.random() * 1.3,
        user: allow ? 'alice' : Math.random() > 0.5 ? 'bob' : 'anon',
      });
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    for (let i = 0; i < 6; i++) {
      spawnPacket();
      packetsRef.current[i].x = 40 + i * 70;
    }

    const render = (now: number) => {
      rafId = requestAnimationFrame(render);
      if (!isVisibleRef.current || width <= 0 || height <= 0) return;

      const gateX = width * 0.47;
      const midY = height * 0.5;
      const allowY = height * 0.28;
      const denyY = height * 0.72;

      if (!pausedRef.current && now - lastSpawn > 520) {
        spawnPacket();
        lastSpawn = now;
      }

      ctx.fillStyle = '#0E0F10';
      ctx.fillRect(0, 0, width, height);

      ctx.strokeStyle = 'rgba(244, 243, 238, 0.055)';
      ctx.lineWidth = 1;
      for (let gx = 0; gx < width; gx += 32) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, height);
        ctx.stroke();
      }
      for (let gy = 0; gy < height; gy += 32) {
        ctx.beginPath();
        ctx.moveTo(0, gy);
        ctx.lineTo(width, gy);
        ctx.stroke();
      }

      ctx.strokeStyle = 'rgba(244, 243, 238, 0.28)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(20, midY);
      ctx.lineTo(gateX, midY);
      ctx.stroke();

      ctx.strokeStyle = 'rgba(42, 199, 138, 0.45)';
      ctx.beginPath();
      ctx.moveTo(gateX, midY);
      ctx.bezierCurveTo(gateX + 60, midY, gateX + 70, allowY, width - 24, allowY);
      ctx.stroke();

      ctx.strokeStyle = 'rgba(230, 59, 46, 0.45)';
      ctx.beginPath();
      ctx.moveTo(gateX, midY);
      ctx.bezierCurveTo(gateX + 60, midY, gateX + 70, denyY, width - 24, denyY);
      ctx.stroke();

      ctx.fillStyle = '#161719';
      ctx.strokeStyle = '#4A4D52';
      ctx.lineWidth = 1;
      const boxW = 92;
      const boxH = 112;
      ctx.fillRect(gateX - boxW / 2, midY - boxH / 2, boxW, boxH);
      ctx.strokeRect(gateX - boxW / 2, midY - boxH / 2, boxW, boxH);

      ctx.fillStyle = '#F4F3EE';
      ctx.font = '600 10px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.fillText('OPA + OIDC', gateX, midY - 14);
      ctx.fillStyle = '#C8C4BA';
      ctx.font = '400 9px "JetBrains Mono", monospace';
      ctx.fillText('ES256 GATE', gateX, midY + 4);
      ctx.fillStyle = '#2AC78A';
      ctx.fillText('FAIL-CLOSED', gateX, midY + 22);

      ctx.textAlign = 'left';
      ctx.fillStyle = '#C8C4BA';
      ctx.font = '500 10px "JetBrains Mono", monospace';
      ctx.fillText('HTTPS :443 INGRESS', 18, midY - 22);

      ctx.textAlign = 'right';
      ctx.fillStyle = '#2AC78A';
      ctx.fillText('200 ALLOW -> mTLS 1.3', width - 18, allowY - 14);
      ctx.fillStyle = '#E63B2E';
      ctx.fillText('403 FAIL-CLOSED DENY', width - 18, denyY + 22);

      const nextPackets: Packet[] = [];
      for (const p of packetsRef.current) {
        if (!pausedRef.current) {
          p.x += p.vx;
          if (!p.decided && p.x >= gateX) {
            p.decided = true;
            if (now - lastStatTick > 160) {
              lastStatTick = now;
              setLiveStats((prev) => ({
                p95: parseFloat((p.allow ? p.latency : prev.p95).toFixed(2)),
                allowed: prev.allowed + (p.allow ? 1 : 0),
                denied: prev.denied + (p.allow ? 0 : 1),
              }));
            }
          }
          if (p.decided) {
            p.y += (p.targetY - p.y) * 0.085;
          } else {
            p.y += (midY - p.y) * 0.06;
          }
        }

        if (p.x < width - 16) {
          nextPackets.push(p);

          const color = !p.decided ? '#F4F3EE' : p.allow ? '#2AC78A' : '#E63B2E';

          ctx.fillStyle = color;
          ctx.fillRect(p.x - 4, p.y - 4, 8, 8);

          ctx.fillStyle = 'rgba(244, 243, 238, 0.85)';
          ctx.font = '400 9px "JetBrains Mono", monospace';
          ctx.textAlign = 'center';
          ctx.fillText(p.user, p.x, p.y - 9);
        }
      }
      packetsRef.current = nextPackets;
    };

    rafId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(rafId);
      ro.disconnect();
    };
  }, []);

  const handleBurst = () => {
    const canvas = canvasRef.current;
    const h = canvas ? canvas.getBoundingClientRect().height : 380;
    for (let i = 0; i < 10; i++) {
      const allow = i % 3 !== 0;
      packetsRef.current.push({
        x: 12 + i * 10,
        y: h * 0.5 + (Math.random() - 0.5) * 32,
        targetY: allow ? h * 0.28 : h * 0.72,
        vx: 2.8 + Math.random() * 1.6,
        allow,
        decided: false,
        latency: allow ? 6.1 + Math.random() * 4.9 : 1.15,
        user: allow ? 'alice' : 'bob',
      });
    }
  };

  const togglePause = () => {
    pausedRef.current = !pausedRef.current;
    setPaused(pausedRef.current);
  };

  return (
    <section
      id="gate"
      ref={rootRef}
      className="relative pt-14 surface-bone bg-[#F4F3EE] text-[#141413] border-b border-[#C9C5BA] arch-grid-bone"
    >
      <div className="max-w-[1440px] mx-auto grid grid-cols-1 lg:grid-cols-12 min-h-[calc(100vh-3.5rem)]">
        {/* Left Editorial Column (7 cols) */}
        <div className="lg:col-span-7 px-6 sm:px-10 lg:px-12 py-12 lg:py-16 flex flex-col justify-between lg:border-r border-[#C9C5BA]">
          <div>
            <div className="hero-fade flex flex-wrap items-center gap-3 font-mono text-[11px] uppercase tracking-[0.14em] text-[#3D3C38] mb-8">
              <span className="px-2 py-0.5 border border-[#141413] text-[#141413] font-semibold">
                V1.0 / ZERO-TRUST INGRESS
              </span>
              <span>OIDC · ES256 POSTURE · OPA REGO · MTLS 1.3</span>
            </div>

            <h1 className="font-serif text-[clamp(3.3rem,7.2vw,6.75rem)] leading-[0.94] tracking-[-0.03em] text-[#141413] mb-8">
              <span className="block overflow-hidden pb-1">
                <span className="hero-line-inner block">Zero Trust.</span>
              </span>
              <span className="block overflow-hidden pb-2">
                <span className="hero-line-inner block">
                  <em className="italic font-normal text-[#141413]">Twelve</em> Milliseconds.
                </span>
              </span>
            </h1>

            <div className="hero-hairline h-px w-full bg-[#C9C5BA] mb-8" />

            <p className="hero-fade max-w-xl text-base sm:text-lg leading-relaxed text-[#3D3C38] mb-10">
              <strong className="font-semibold text-[#141413]">Doorman</strong> is an identity-aware
              reverse proxy in Go 1.22. Every incoming request must prove identity via Keycloak OIDC,
              cryptographic device posture via ES256, and contextual authorization via Open Policy
              Agent before touching an upstream mTLS backend.
            </p>

            <div className="hero-fade flex flex-wrap items-center gap-4">
              <button
                type="button"
                onClick={() => onNavigate('dispatch')}
                className="group inline-flex items-center gap-3 px-6 py-3.5 bg-[#141413] text-[#F4F3EE] font-mono text-xs font-medium uppercase tracking-[0.12em] hover:bg-[#1B7F5C] transition-colors duration-300 ease-expo"
              >
                <span>Launch Live Dispatch</span>
                <ArrowDownRight className="w-4 h-4 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:translate-y-0.5" />
              </button>

              <button
                type="button"
                onClick={() => onNavigate('cloud')}
                className="inline-flex items-center gap-2 px-6 py-3.5 border border-[#141413] text-[#141413] font-mono text-xs font-medium uppercase tracking-[0.12em] hover:bg-[#EAE8E0] transition-colors duration-200"
              >
                <span>Inspect K8s & Docker</span>
              </button>
            </div>
          </div>

          {/* Bottom 4-cell Spec Bar */}
          <div className="hero-fade mt-12 pt-8 border-t border-[#C9C5BA] grid grid-cols-2 sm:grid-cols-4 gap-6 font-mono">
            <div>
              <div className="text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-1">
                SLA Ceiling
              </div>
              <div className="text-lg font-semibold tabular-nums text-[#141413]">&lt; 12.00 ms</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-1">
                Peak Throughput
              </div>
              <div className="text-lg font-semibold tabular-nums text-[#141413]">7,820 rps</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-1">
                Posture Proof
              </div>
              <div className="text-lg font-semibold text-[#141413]">ECDSA P-256</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.14em] text-[#3D3C38] mb-1">
                Gate Semantics
              </div>
              <div className="text-lg font-semibold text-[#E63B2E]">Fail-Closed</div>
            </div>
          </div>
        </div>

        {/* Right Telemetry Canvas Column (5 cols) */}
        <div className="lg:col-span-5 surface-carbon bg-[#0E0F10] text-[#F4F3EE] flex flex-col justify-between p-6 sm:p-8">
          <div className="flex items-center justify-between border-b border-[#2A2D31] pb-4">
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#C8C4BA]">
                Oscilloscope / Gate Telemetry
              </div>
              <div className="font-mono text-sm font-semibold text-[#F4F3EE] mt-0.5">
                Live Packet Inspection Stream
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleBurst}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-[#3A3D42] hover:border-[#F4F3EE] font-mono text-[11px] uppercase tracking-wider text-[#F4F3EE] transition-colors"
              >
                <Plus className="w-3 h-3" />
                <span>Burst 10</span>
              </button>
              <button
                type="button"
                onClick={togglePause}
                aria-label={paused ? 'Resume stream' : 'Pause stream'}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-[#3A3D42] hover:border-[#F4F3EE] font-mono text-[11px] uppercase tracking-wider text-[#F4F3EE] transition-colors"
              >
                {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
              </button>
            </div>
          </div>

          <div className="relative my-6 flex-1 min-h-[300px] border border-[#2A2D31] bg-[#0E0F10]">
            <canvas ref={canvasRef} className="w-full h-full block" />
          </div>

          <div className="grid grid-cols-3 border border-[#2A2D31] divide-x divide-[#2A2D31] font-mono bg-[#161719]">
            <div className="p-3.5">
              <div className="text-[10px] uppercase tracking-wider text-[#C8C4BA]">Gate p95</div>
              <div className="text-base font-semibold tabular-nums text-[#2AC78A] mt-1">
                {liveStats.p95.toFixed(2)} ms
              </div>
            </div>
            <div className="p-3.5">
              <div className="text-[10px] uppercase tracking-wider text-[#C8C4BA]">200 Allow</div>
              <div className="text-base font-semibold tabular-nums text-[#F4F3EE] mt-1">
                {liveStats.allowed}
              </div>
            </div>
            <div className="p-3.5">
              <div className="text-[10px] uppercase tracking-wider text-[#C8C4BA]">403 Blocked</div>
              <div className="text-base font-semibold tabular-nums text-[#E63B2E] mt-1">
                {liveStats.denied}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
