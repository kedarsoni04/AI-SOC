/**
 * Settings Page
 */
import { useState } from 'react';
import { Settings, Key, Bell, Database, Shield } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';

export function SettingsPage() {
  const [geminiKey, setGeminiKey] = useState('');
  const [saved, setSaved] = useState(false);

  const save = () => {
    localStorage.setItem('GEMINI_API_KEY_HINT', geminiKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Settings" subtitle="Platform configuration" />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
            <Key className="w-4 h-4 text-soc-primary" />
            AI / LLM Configuration
          </h3>
          <div className="space-y-3 text-xs">
            <div>
              <p className="text-soc-text-muted mb-1">Set your Gemini API key in <span className="font-mono text-soc-primary">backend/.env</span></p>
              <code className="block p-3 bg-soc-surface rounded-lg font-mono text-soc-text-dim">
                GEMINI_API_KEY=your_api_key_here<br />
                LLM_PROVIDER=gemini<br />
                LLM_MODEL=gemini-1.5-flash
              </code>
            </div>
            <p className="text-soc-text-muted">The platform gracefully falls back to rule-based investigation if no API key is configured.</p>
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
            <Database className="w-4 h-4 text-soc-primary" />
            Database
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between py-2 border-b border-soc-border/50">
              <span className="text-soc-text-muted">Database URL</span>
              <span className="font-mono text-soc-text-dim">From DATABASE_URL env var</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-soc-border/50">
              <span className="text-soc-text-muted">ORM</span>
              <span className="font-mono text-soc-text-dim">SQLAlchemy (async)</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-soc-text-muted">Default DB (dev)</span>
              <span className="font-mono text-soc-text-dim">SQLite (soc.db)</span>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-soc-primary" />
            Security
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between py-2 border-b border-soc-border/50">
              <span className="text-soc-text-muted">Authentication</span>
              <span className="text-soc-text-dim">JWT (RS256/HS256)</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-soc-border/50">
              <span className="text-soc-text-muted">Access Token TTL</span>
              <span className="text-soc-text-dim">30 minutes</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-soc-text-muted">Refresh Token TTL</span>
              <span className="text-soc-text-dim">7 days</span>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
            <Settings className="w-4 h-4 text-soc-primary" />
            Project Info
          </h3>
          <div className="space-y-2 text-xs text-soc-text-muted">
            <p>AI-Powered Cybersecurity SOC Platform</p>
            <p>Final Year B.Tech Computer Science Project</p>
            <div className="mt-3 grid grid-cols-2 gap-2">
              {[
                ['Backend', 'Python FastAPI'],
                ['Frontend', 'React + TypeScript + Vite'],
                ['Database', 'PostgreSQL / SQLite'],
                ['ML Models', 'Isolation Forest + Random Forest'],
                ['Real-time', 'WebSockets'],
                ['AI', 'Google Gemini (configurable)'],
              ].map(([label, value]) => (
                <div key={label} className="bg-soc-surface rounded p-2">
                  <p className="text-soc-text-dim font-medium">{label}</p>
                  <p className="text-soc-text-muted">{value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
