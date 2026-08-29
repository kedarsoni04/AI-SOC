/**
 * Login Page
 */
import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, AlertCircle, Lock, User } from 'lucide-react';
import { useAuthStore } from '../store/authStore';

export function LoginPage() {
  const { isAuthenticated, login, isLoading, error, clearError } = useAuthStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  if (isAuthenticated) return <Navigate to="/" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    try {
      await login({ username, password });
    } catch {
      // Error handled in store
    }
  };

  return (
    <div className="min-h-screen bg-soc-bg flex items-center justify-center relative overflow-hidden">
      {/* Background grid */}
      <div className="absolute inset-0 bg-grid opacity-30" />
      
      {/* Glow orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-soc-primary/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-soc-secondary/5 rounded-full blur-3xl" />

      <div className="relative z-10 w-full max-w-sm mx-auto px-6">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-soc-primary/10 border border-soc-primary/30 rounded-2xl mb-4 glow-primary">
            <Shield className="w-8 h-8 text-soc-primary" />
          </div>
          <h1 className="text-2xl font-bold text-soc-text">AI-SOC Platform</h1>
          <p className="text-sm text-soc-text-muted mt-1">Security Operations Center</p>
        </div>

        {/* Card */}
        <div className="card-lg border-soc-border-light shadow-2xl">
          <h2 className="text-base font-semibold text-soc-text mb-6">Sign in to SOC</h2>

          {error && (
            <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-soc-text-dim mb-1.5">
                Username or Email
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-text-muted" />
                <input
                  type="text"
                  className="input pl-9"
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-soc-text-dim mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-text-muted" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="input pl-9 pr-10"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-soc-text-muted hover:text-soc-text"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn-primary w-full justify-center py-2.5"
              disabled={isLoading}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-soc-bg/30 border-t-soc-bg rounded-full animate-spin" />
                  Authenticating...
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Default credentials hint */}
          <div className="mt-4 p-3 bg-soc-surface rounded-lg border border-soc-border text-xs text-soc-text-muted">
            <p className="font-medium text-soc-text-dim mb-1">Default credentials:</p>
            <div className="space-y-0.5 font-mono">
              <p>admin / Admin@123 (admin)</p>
              <p>analyst / Analyst@123 (analyst)</p>
              <p>viewer / Viewer@123 (viewer)</p>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-soc-text-muted mt-6">
          AI-Powered SOC · Final Year B.Tech Project
        </p>
      </div>
    </div>
  );
}
