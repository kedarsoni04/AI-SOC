/**
 * Attack Map Page — SVG world map with attack source visualization
 */
import { useState, useEffect } from 'react';
import { Globe } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { get } from '../services/api';
import type { GeoAttack } from '../types';

// Simple equirectangular projection
const toSVG = (lat: number, lon: number, w = 1000, h = 500) => ({
  x: (lon + 180) * (w / 360),
  y: (90 - lat) * (h / 180),
});

const COUNTRY_COLORS: Record<string, string> = {
  'Russia': '#ef4444',
  'China': '#f97316',
  'United States': '#f59e0b',
  'Germany': '#3b82f6',
  'Ukraine': '#8b5cf6',
  'France': '#06b6d4',
  'Netherlands': '#10b981',
  'Unknown': '#64748b',
};

export function AttackMapPage() {
  const [attacks, setAttacks] = useState<GeoAttack[]>([]);
  const [selected, setSelected] = useState<GeoAttack | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await get<GeoAttack[]>('/dashboard/geo-attacks');
        setAttacks(data);
      } finally {
        setIsLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  const maxCount = Math.max(...attacks.map(a => a.count), 1);

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Attack Map"
        subtitle={`${attacks.length} attack sources detected`}
      />
      <div className="flex-1 overflow-auto p-6 space-y-4">
        <div className="card relative overflow-hidden" style={{ height: 420 }}>
          {/* Background */}
          <div className="absolute inset-0 bg-soc-bg rounded-lg">
            {/* Grid lines */}
            <svg className="w-full h-full opacity-10" viewBox="0 0 1000 500">
              {/* Longitude lines */}
              {[-150,-120,-90,-60,-30,0,30,60,90,120,150].map(lon => {
                const x = (lon + 180) * (1000 / 360);
                return <line key={lon} x1={x} y1={0} x2={x} y2={500} stroke="#1e2d40" strokeWidth={0.5} />;
              })}
              {/* Latitude lines */}
              {[-60,-30,0,30,60].map(lat => {
                const y = (90 - lat) * (500 / 180);
                return <line key={lat} x1={0} y1={y} x2={1000} y2={y} stroke="#1e2d40" strokeWidth={0.5} />;
              })}
            </svg>

            {/* Attack markers */}
            <svg
              className="absolute inset-0 w-full h-full"
              viewBox="0 0 1000 500"
              preserveAspectRatio="xMidYMid meet"
            >
              {attacks.map((attack, i) => {
                if (!attack.lat || !attack.lon) return null;
                const { x, y } = toSVG(attack.lat, attack.lon);
                const radius = 4 + (attack.count / maxCount) * 12;
                const color = COUNTRY_COLORS[attack.country] || '#ef4444';
                return (
                  <g key={i} onClick={() => setSelected(attack)} className="cursor-pointer">
                    {/* Pulse ring */}
                    <circle cx={x} cy={y} r={radius * 2} fill={color} fillOpacity={0.1}>
                      <animate attributeName="r" from={radius} to={radius * 2.5} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" from={0.3} to={0} dur="2s" repeatCount="indefinite" />
                    </circle>
                    {/* Core dot */}
                    <circle cx={x} cy={y} r={radius} fill={color} fillOpacity={0.8} stroke={color} strokeWidth={1} />
                    <text x={x + radius + 2} y={y + 4} fontSize={8} fill="#94a3b8">{attack.ip}</text>
                  </g>
                );
              })}

              {/* Target city — center of network (assume datacenter in India) */}
              <g>
                <circle cx={toSVG(19.08, 72.88).x} cy={toSVG(19.08, 72.88).y} r={6} fill="#00d4ff" fillOpacity={0.9} />
                <text x={toSVG(19.08, 72.88).x + 8} y={toSVG(19.08, 72.88).y + 4} fontSize={8} fill="#00d4ff">Target</text>
              </g>
            </svg>
          </div>

          {/* Legend */}
          <div className="absolute top-4 right-4 bg-soc-surface/90 border border-soc-border rounded-lg p-3 text-xs space-y-1">
            {Object.entries(COUNTRY_COLORS).filter(([k]) => k !== 'Unknown').map(([country, color]) => (
              <div key={country} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-soc-text-muted">{country}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="card overflow-auto max-h-64">
          <table className="table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Country</th>
                <th>City</th>
                <th>Attack Count</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map(a => (
                <tr key={a.ip} onClick={() => setSelected(a)} className={selected?.ip === a.ip ? 'bg-soc-primary/10' : ''}>
                  <td className="font-mono text-xs text-soc-primary">{a.ip}</td>
                  <td className="text-xs">{a.country}</td>
                  <td className="text-xs text-soc-text-muted">{a.city || '—'}</td>
                  <td className="text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-soc-border rounded-full h-1">
                        <div className="bg-red-500 h-1 rounded-full" style={{ width: `${(a.count / maxCount) * 100}%` }} />
                      </div>
                      {a.count}
                    </div>
                  </td>
                </tr>
              ))}
              {attacks.length === 0 && (
                <tr><td colSpan={4} className="text-center py-8 text-soc-text-muted">
                  No geo-located attacks yet. Run a simulation.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
