/**
 * Severity and status badge components
 */
import type { Severity, AlertStatus, IncidentStatus } from '../../types';
import clsx from 'clsx';

type BadgeVariant = Severity | AlertStatus | IncidentStatus | string;

const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
};

const STATUS_CLASSES: Record<string, string> = {
  new: 'badge-new',
  acknowledged: 'badge-medium',
  investigating: 'badge-investigating',
  contained: 'badge-contained',
  resolved: 'badge-resolved',
  false_positive: 'badge-false-positive',
  pending: 'badge-medium',
  approved: 'badge-resolved',
  executed: 'badge-resolved',
  rejected: 'badge-critical',
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span className={clsx(SEVERITY_CLASSES[severity] || 'badge-info', className)}>
      {severity?.toUpperCase()}
    </span>
  );
}

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const label = status?.replace(/_/g, ' ').toUpperCase();
  return (
    <span className={clsx(STATUS_CLASSES[status] || 'badge', className)}>
      {label}
    </span>
  );
}

interface SeverityDotProps {
  severity: Severity;
}

export function SeverityDot({ severity }: SeverityDotProps) {
  return <span className={`status-dot-${severity}`} />;
}

interface RiskScoreBadgeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export function RiskScoreBadge({ score, size = 'md' }: RiskScoreBadgeProps) {
  const color =
    score >= 80 ? 'text-red-400 bg-red-500/20 border-red-500/30' :
    score >= 60 ? 'text-orange-400 bg-orange-500/20 border-orange-500/30' :
    score >= 40 ? 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30' :
    'text-blue-400 bg-blue-500/20 border-blue-500/30';
  
  const sizeClass = size === 'lg' ? 'text-2xl font-bold px-4 py-2' :
                    size === 'sm' ? 'text-xs px-2 py-0.5' :
                    'text-sm font-semibold px-3 py-1';
  
  return (
    <span className={clsx('inline-flex items-center rounded-lg border font-mono', color, sizeClass)}>
      {score.toFixed(0)}
    </span>
  );
}
