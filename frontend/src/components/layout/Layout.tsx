/**
 * Main application sidebar + layout shell
 */
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Shield, Activity, AlertTriangle, Siren, Globe, Target,
  Brain, Terminal, FileText, Settings, LogOut, Wifi, WifiOff,
  ChevronRight, Zap, Database, Users
} from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import clsx from 'clsx';

const NAV_ITEMS = [
  { to: '/', label: 'SOC Dashboard', icon: Activity, end: true },
  { to: '/events', label: 'Live Events', icon: Zap },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/incidents', label: 'Incidents', icon: Siren },
  { to: '/threat-intel', label: 'Threat Intel', icon: Database },
  { to: '/attack-map', label: 'Attack Map', icon: Globe },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: Target },
  { to: '/ml-analytics', label: 'ML Analytics', icon: Brain },
  { to: '/response', label: 'Response Center', icon: Terminal },
  { to: '/audit-logs', label: 'Audit Logs', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
];

interface LayoutProps {
  children: React.ReactNode;
  wsConnected?: boolean;
}

export function Layout({ children, wsConnected = false }: LayoutProps) {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen bg-soc-bg overflow-hidden">
      {/* ── Sidebar ─────────────────────────────────────────────────── */}
      <aside className="w-60 flex-shrink-0 bg-soc-surface border-r border-soc-border flex flex-col">
        {/* Logo */}
        <div className="h-14 flex items-center gap-3 px-4 border-b border-soc-border">
          <div className="w-8 h-8 bg-soc-primary/20 border border-soc-primary/40 rounded-lg flex items-center justify-center">
            <Shield className="w-4 h-4 text-soc-primary" />
          </div>
          <div>
            <p className="text-sm font-semibold text-soc-text leading-tight">AI-SOC</p>
            <p className="text-xs text-soc-text-muted leading-tight">Platform</p>
          </div>
          <div className="ml-auto">
            {wsConnected ? (
              <div className="flex items-center gap-1">
                <Wifi className="w-3 h-3 text-green-500" />
                <span className="text-xs text-green-500">LIVE</span>
              </div>
            ) : (
              <div className="flex items-center gap-1">
                <WifiOff className="w-3 h-3 text-soc-text-muted" />
                <span className="text-xs text-soc-text-muted">OFF</span>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx('nav-item', isActive && 'nav-item-active')
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span className="flex-1">{label}</span>
              <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100" />
            </NavLink>
          ))}
        </nav>

        {/* User footer */}
        <div className="border-t border-soc-border p-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 bg-soc-primary/20 rounded-full flex items-center justify-center">
              <Users className="w-3.5 h-3.5 text-soc-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-soc-text truncate">{user?.username}</p>
              <p className="text-xs text-soc-text-muted capitalize">{user?.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="p-1.5 rounded hover:bg-soc-border text-soc-text-muted hover:text-red-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
