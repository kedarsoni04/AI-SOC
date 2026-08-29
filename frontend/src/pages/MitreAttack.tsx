/**
 * MITRE ATT&CK Page
 */
import { useState, useEffect } from 'react';
import { Target } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { get } from '../services/api';



const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access', color: '#ef4444' },
  { id: 'TA0002', name: 'Execution', color: '#f97316' },
  { id: 'TA0003', name: 'Persistence', color: '#f59e0b' },
  { id: 'TA0004', name: 'Privilege Escalation', color: '#eab308' },
  { id: 'TA0005', name: 'Defense Evasion', color: '#84cc16' },
  { id: 'TA0006', name: 'Credential Access', color: '#22c55e' },
  { id: 'TA0007', name: 'Discovery', color: '#06b6d4' },
  { id: 'TA0008', name: 'Lateral Movement', color: '#3b82f6' },
  { id: 'TA0009', name: 'Collection', color: '#8b5cf6' },
  { id: 'TA0010', name: 'Exfiltration', color: '#ec4899' },
];

export function MitreAttackPage() {
  const [detectedTactics, setDetectedTactics] = useState<Set<string>>(new Set());


  useEffect(() => {
    const load = async () => {
      try {
        // Fetch all incidents to collect MITRE tactics
        const data = await get<{ items: { mitre_tactics?: string[] }[] }>('/incidents', { page: 1, page_size: 100 });
        const tactics = new Set<string>();
        data.items.forEach(inc => {
          (inc.mitre_tactics || []).forEach(t => {
            const tacticId = t.split(' ')[0];
            tactics.add(tacticId);
          });
        });
        setDetectedTactics(tactics);
      } catch (err) {
        console.error(err);
      }
    };
    load();
  }, []);

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="MITRE ATT&CK" subtitle="Observed tactics and techniques from detected incidents" />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* Tactics Grid */}
        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
            <Target className="w-4 h-4 text-soc-secondary" />
            ATT&CK Tactic Coverage
          </h3>
          <div className="grid grid-cols-5 gap-3">
            {MITRE_TACTICS.map(tactic => {
              const detected = detectedTactics.has(tactic.id);
              return (
                <div
                  key={tactic.id}
                  className={`p-3 rounded-lg border text-xs transition-all ${
                    detected
                      ? 'border-opacity-50 text-white'
                      : 'border-soc-border text-soc-text-muted opacity-40'
                  }`}
                  style={detected ? { borderColor: tactic.color, backgroundColor: `${tactic.color}15` } : {}}
                >
                  <div className="flex items-center gap-1 mb-1">
                    <div
                      className={`w-2 h-2 rounded-full ${detected ? 'animate-pulse' : ''}`}
                      style={{ backgroundColor: detected ? tactic.color : '#4b5563' }}
                    />
                    <span className="font-mono text-xs">{tactic.id}</span>
                  </div>
                  <p className="font-medium leading-tight" style={detected ? { color: tactic.color } : {}}>
                    {tactic.name}
                  </p>
                  {detected && (
                    <span className="mt-1 inline-block text-xs px-1 py-0.5 rounded" style={{ backgroundColor: `${tactic.color}30`, color: tactic.color }}>
                      DETECTED
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-3 gap-4">
          <div className="card text-center">
            <p className="text-3xl font-bold font-mono text-soc-primary">{detectedTactics.size}</p>
            <p className="text-xs text-soc-text-muted">Tactics Observed</p>
          </div>
          <div className="card text-center">
            <p className="text-3xl font-bold font-mono text-soc-secondary">{MITRE_TACTICS.length}</p>
            <p className="text-xs text-soc-text-muted">Total Tactics</p>
          </div>
          <div className="card text-center">
            <p className="text-3xl font-bold font-mono text-yellow-400">
              {Math.round((detectedTactics.size / MITRE_TACTICS.length) * 100)}%
            </p>
            <p className="text-xs text-soc-text-muted">Coverage</p>
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-3">Common Technique Mappings</h3>
          <div className="space-y-2 text-xs">
            {[
              { tactic: 'Credential Access (TA0006)', technique: 'T1110 - Brute Force', desc: 'Repeated login failures' },
              { tactic: 'Initial Access (TA0001)', technique: 'T1190 - Exploit Public-Facing App', desc: 'SQL Injection attempts' },
              { tactic: 'Discovery (TA0007)', technique: 'T1046 - Network Service Scanning', desc: 'Port scan activity' },
              { tactic: 'Privilege Escalation (TA0004)', technique: 'T1068 - Exploitation for Priv Esc', desc: 'Privilege change events' },
              { tactic: 'Exfiltration (TA0010)', technique: 'T1041 - Exfiltration Over C2', desc: 'Large outbound transfers' },
              { tactic: 'Initial Access (TA0001)', technique: 'T1078 - Valid Accounts', desc: 'Credential compromise / impossible travel' },
            ].map((item, i) => (
              <div key={i} className="grid grid-cols-3 gap-4 py-2 border-b border-soc-border/50">
                <span className="text-purple-300">{item.tactic}</span>
                <span className="text-soc-primary font-mono">{item.technique}</span>
                <span className="text-soc-text-muted">{item.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
