import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import { Layout } from './components/layout/Layout';
import { useWebSocket } from './hooks/useWebSocket';
import { LoginPage } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { LiveEventsPage } from './pages/LiveEvents';
import { AlertsPage } from './pages/Alerts';
import { IncidentsPage } from './pages/Incidents';
import { IncidentInvestigation } from './pages/IncidentInvestigation';
import { ThreatIntelPage } from './pages/ThreatIntelligence';
import { AttackMapPage } from './pages/AttackMap';
import { MitreAttackPage } from './pages/MitreAttack';
import { MLAnalyticsPage } from './pages/MLAnalytics';
import { ResponseCenterPage } from './pages/ResponseCenter';
import { AuditLogsPage } from './pages/AuditLogs';
import { SettingsPage } from './pages/Settings';

function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  const { isConnected } = useWebSocket();

  if (!isAuthenticated) return <Navigate to="/login" replace />;

  return <Layout wsConnected={isConnected}>{children}</Layout>;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />

        <Route
          path="/"
          element={<ProtectedLayout><Dashboard /></ProtectedLayout>}
        />
        <Route
          path="/events"
          element={<ProtectedLayout><LiveEventsPage /></ProtectedLayout>}
        />
        <Route
          path="/alerts"
          element={<ProtectedLayout><AlertsPage /></ProtectedLayout>}
        />
        <Route
          path="/incidents"
          element={<ProtectedLayout><IncidentsPage /></ProtectedLayout>}
        />
        <Route
          path="/incidents/:id"
          element={<ProtectedLayout><IncidentInvestigation /></ProtectedLayout>}
        />
        <Route
          path="/threat-intel"
          element={<ProtectedLayout><ThreatIntelPage /></ProtectedLayout>}
        />
        <Route
          path="/attack-map"
          element={<ProtectedLayout><AttackMapPage /></ProtectedLayout>}
        />
        <Route
          path="/mitre"
          element={<ProtectedLayout><MitreAttackPage /></ProtectedLayout>}
        />
        <Route
          path="/ml-analytics"
          element={<ProtectedLayout><MLAnalyticsPage /></ProtectedLayout>}
        />
        <Route
          path="/response"
          element={<ProtectedLayout><ResponseCenterPage /></ProtectedLayout>}
        />
        <Route
          path="/audit-logs"
          element={<ProtectedLayout><AuditLogsPage /></ProtectedLayout>}
        />
        <Route
          path="/settings"
          element={<ProtectedLayout><SettingsPage /></ProtectedLayout>}
        />

        {/* Catch-all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
