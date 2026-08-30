/**
 * Attack Map Page — SVG world map with attack source visualization
 */
import { useState, useEffect } from 'react';

import { PageHeader } from '../components/layout/PageHeader';
import { get } from '../services/api';
import type { GeoAttack } from '../types';

import { geoMercator, geoPath } from 'd3-geo';

const geoUrl = "https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson";

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

// Map configuration
const width = 1000;
const height = 420;
const projection = geoMercator().scale(120).translate([width / 2, height / 1.5]);
const pathGenerator = geoPath().projection(projection);

export function AttackMapPage() {
  const [attacks, setAttacks] = useState<GeoAttack[]>([]);
  const [selected, setSelected] = useState<GeoAttack | null>(null);
  const [geographies, setGeographies] = useState<any[]>([]);

  useEffect(() => {
    // Load world map GeoJSON
    fetch(geoUrl)
      .then(res => res.json())
      .then(data => {
        if (data && data.features) setGeographies(data.features);
      })
      .catch(console.error);

    // Load attacks
    const load = async () => {
      try {
        const data = await get<GeoAttack[]>('/dashboard/geo-attacks');
        setAttacks(data);
      } catch (err) {
        console.error(err);
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
        <div className="card relative overflow-hidden bg-soc-bg rounded-lg" style={{ height: 420 }}>
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full">
            {/* Base Map */}
            <g>
              {geographies.map((geo, i) => (
                <path
                  key={i}
                  d={pathGenerator(geo) || ""}
                  fill="#1e2d40"
                  stroke="#0f172a"
                  strokeWidth={0.5}
                  className="hover:fill-[#293c56] transition-colors"
                />
              ))}
            </g>

            {/* Attack Markers */}
            <g>
              {attacks.map((attack, i) => {
                if (!attack.lat || !attack.lon) return null;
                const coords = projection([attack.lon, attack.lat]);
                if (!coords) return null;
                const [x, y] = coords;
                
                const radius = 4 + (attack.count / maxCount) * 12;
                const color = COUNTRY_COLORS[attack.country] || '#ef4444';
                return (
                  <g key={i} onClick={() => setSelected(attack)} className="cursor-pointer">
                    <circle cx={x} cy={y} r={radius * 2} fill={color} fillOpacity={0.1}>
                      <animate attributeName="r" from={radius} to={radius * 2.5} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" from={0.3} to={0} dur="2s" repeatCount="indefinite" />
                    </circle>
                    <circle cx={x} cy={y} r={radius} fill={color} fillOpacity={0.8} stroke={color} strokeWidth={1} />
                    <text x={x} y={y + radius + 8} textAnchor="middle" fontSize={8} fill="#94a3b8">{attack.ip}</text>
                  </g>
                );
              })}
            </g>

            {/* Target Datacenter Marker */}
            <g>
              {projection([72.88, 19.08]) && (
                <>
                  <circle cx={projection([72.88, 19.08])![0]} cy={projection([72.88, 19.08])![1]} r={6} fill="#00d4ff" fillOpacity={0.9} />
                  <text x={projection([72.88, 19.08])![0]} y={projection([72.88, 19.08])![1] + 14} textAnchor="middle" fontSize={8} fill="#00d4ff">Target</text>
                </>
              )}
            </g>
          </svg>

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
