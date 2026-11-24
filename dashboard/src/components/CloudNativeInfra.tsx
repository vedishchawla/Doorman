import React, { useEffect, useState } from 'react';
import { Container, Layers, RefreshCw, Shield } from 'lucide-react';
import { fetchInfraStatus } from '../api';
import { InfraStatus } from '../types';

export const CloudNativeInfra: React.FC = () => {
  const [tab, setTab] = useState<'docker' | 'k8s'>('docker');
  const [infra, setInfra] = useState<InfraStatus | null>(null);
  const [selectedManifest, setSelectedManifest] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const loadInfra = async () => {
    setLoading(true);
    try {
      const data = await fetchInfraStatus();
      setInfra(data);
      if (data.k8sManifests.length > 0 && !selectedManifest) {
        setSelectedManifest(data.k8sManifests[0].name);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInfra();
  }, []);

  const currentManifest = infra?.k8sManifests.find((m) => m.name === selectedManifest);

  return (
    <section
      id="cloud"
      className="surface-bone bg-[#F4F3EE] text-[#141413] border-b border-[#C9C5BA] py-20 lg:py-28"
    >
      <div className="max-w-[1440px] mx-auto px-6 sm:px-10 lg:px-12">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-10 border-b border-[#C9C5BA]">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#3D3C38] mb-3">
              07 / DOCKER &amp; KUBERNETES TOPOLOGY
            </div>
            <h2 className="font-serif text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] tracking-[-0.02em] text-[#141413]">
              Containerized <em className="italic font-normal">&amp;</em> Orchestrated.
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex border border-[#C9C5BA] divide-x divide-[#C9C5BA] bg-[#EAE8E0] font-mono text-xs">
              <button
                type="button"
                onClick={() => setTab('docker')}
                className={`inline-flex items-center gap-2 px-4 py-2 transition-colors ${
                  tab === 'docker'
                    ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                    : 'text-[#3D3C38] hover:text-[#141413]'
                }`}
              >
                <Container className="w-3.5 h-3.5" />
                <span>DOCKER COMPOSE</span>
              </button>
              <button
                type="button"
                onClick={() => setTab('k8s')}
                className={`inline-flex items-center gap-2 px-4 py-2 transition-colors ${
                  tab === 'k8s'
                    ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                    : 'text-[#3D3C38] hover:text-[#141413]'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>KUBERNETES (K8S)</span>
              </button>
            </div>

            <button
              type="button"
              onClick={loadInfra}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3 py-2 border border-[#C9C5BA] hover:border-[#141413] font-mono text-xs text-[#141413] transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>SYNC</span>
            </button>
          </div>
        </div>

        {tab === 'docker' ? (
          <div className="pt-10 space-y-8">
            {/* Status Strip */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-5 border border-[#C9C5BA] bg-[#EAE8E0] font-mono text-xs">
              <div className="flex items-center gap-3">
                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                    infra?.dockerRunning ? 'bg-[#1B7F5C]' : 'bg-[#D97706]'
                  }`}
                />
                <span className="font-semibold text-[#141413] uppercase tracking-wider">
                  {infra?.dockerRunning
                    ? 'Docker Compose Stack Running (zt-net bridge)'
                    : 'Docker Compose Standby — Run `make up` to boot containers'}
                </span>
              </div>
              <code className="px-2.5 py-1 bg-[#F4F3EE] border border-[#C9C5BA] text-[#141413]">
                make up &amp;&amp; make test
              </code>
            </div>

            {/* Container Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {(infra?.containers || []).map((c) => {
                const isUp =
                  c.state.toLowerCase() === 'running' || c.health.toLowerCase() === 'healthy';
                return (
                  <div
                    key={c.name}
                    className="border border-[#C9C5BA] bg-[#EAE8E0]/80 p-5 flex flex-col justify-between gap-4"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38]">
                          SERVICE
                        </div>
                        <div className="font-mono text-base font-semibold text-[#141413] mt-0.5">
                          {c.service}
                        </div>
                      </div>
                      <span
                        className={`px-2 py-0.5 font-mono text-[10px] uppercase border ${
                          isUp
                            ? 'border-[#1B7F5C] bg-[#1B7F5C]/15 text-[#1B7F5C] font-semibold'
                            : 'border-[#C9C5BA] bg-[#F4F3EE] text-[#3D3C38]'
                        }`}
                      >
                        {c.health || c.state}
                      </span>
                    </div>

                    <div className="pt-3 border-t border-[#C9C5BA] font-mono text-[11px] text-[#3D3C38] space-y-1">
                      <div className="truncate">Container: {c.name}</div>
                      <div className="truncate">Ports: {c.ports || 'internal bridge'}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="pt-10 space-y-8">
            {/* K8s Zero-Trust Topology Schematic */}
            <div className="border border-[#2A2D31] surface-carbon bg-[#0E0F10] text-[#F4F3EE] p-6">
              <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#2A2D31] font-mono text-xs">
                <div className="flex items-center gap-2 text-[#2AC78A]">
                  <Shield className="w-4 h-4" />
                  <span className="uppercase tracking-wider font-semibold">
                    Namespace: doorman · Default-Deny NetworkPolicy Enforced
                  </span>
                </div>
                <span className="text-[#C8C4BA]">HPA: 2–10 Replicas (CPU 70%)</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-6 font-mono text-xs">
                <div className="border border-[#2A2D31] bg-[#161719] p-4">
                  <div className="text-[10px] text-[#C8C4BA] uppercase">01 Edge LoadBalancer</div>
                  <div className="text-[#F4F3EE] font-semibold mt-1">nginx-ingress (:443)</div>
                  <div className="text-[11px] text-[#C8C4BA] mt-2">
                    TLS termination &rarr; proxy ClusterIP
                  </div>
                </div>
                <div className="border border-[#1B7F5C] bg-[#122E24] p-4">
                  <div className="text-[10px] text-[#2AC78A] uppercase">02 Autoscaled Gate</div>
                  <div className="text-[#F4F3EE] font-semibold mt-1">doorman-proxy (HPA 2..10)</div>
                  <div className="text-[11px] text-[#E2DFD7] mt-2">
                    Non-root distroless · :8080 &amp; :9090 metrics
                  </div>
                </div>
                <div className="border border-[#2A2D31] bg-[#161719] p-4">
                  <div className="text-[10px] text-[#C8C4BA] uppercase">03 Auth &amp; Policy</div>
                  <div className="text-[#F4F3EE] font-semibold mt-1">keycloak + opa (x2)</div>
                  <div className="text-[11px] text-[#C8C4BA] mt-2">
                    NetworkPolicy: ingress only from proxy
                  </div>
                </div>
                <div className="border border-[#E63B2E] bg-[#3B1614] p-4">
                  <div className="text-[10px] text-[#FF6B5E] uppercase">04 Isolated Workloads</div>
                  <div className="text-[#F4F3EE] font-semibold mt-1">backend-a &amp; backend-b</div>
                  <div className="text-[11px] text-[#E2DFD7] mt-2">
                    Double isolation: NetPol + mTLS 1.3
                  </div>
                </div>
              </div>
            </div>

            {/* Interactive K8s Manifest Browser */}
            <div className="grid grid-cols-1 lg:grid-cols-12 border border-[#C9C5BA]">
              <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-[#C9C5BA] bg-[#EAE8E0] divide-y divide-[#C9C5BA]">
                <div className="px-4 py-3 font-mono text-[10px] uppercase tracking-[0.14em] text-[#3D3C38]">
                  k8s/ Manifests ({infra?.k8sManifests.length || 0})
                </div>
                {(infra?.k8sManifests || []).map((m) => (
                  <button
                    key={m.name}
                    type="button"
                    onClick={() => setSelectedManifest(m.name)}
                    className={`w-full text-left px-4 py-3 font-mono text-xs transition-colors ${
                      selectedManifest === m.name
                        ? 'bg-[#141413] text-[#F4F3EE] font-semibold'
                        : 'text-[#141413] hover:bg-[#F4F3EE]'
                    }`}
                  >
                    k8s/{m.name}
                  </button>
                ))}
              </div>

              <div className="lg:col-span-8 surface-carbon bg-[#0E0F10] text-[#F4F3EE] p-5 overflow-auto max-h-[420px]">
                <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#2A2D31] font-mono text-[11px]">
                  <span className="text-[#2AC78A]">
                    {currentManifest ? `k8s/${currentManifest.name}` : 'Select a manifest'}
                  </span>
                  <span className="text-[#C8C4BA]">kubectl apply -f k8s/</span>
                </div>
                <pre className="font-mono text-[11px] text-[#E2DFD7] leading-relaxed whitespace-pre">
                  {currentManifest?.content || '# No manifests loaded yet.'}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
