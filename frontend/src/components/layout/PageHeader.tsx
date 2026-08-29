/**
 * Page header with title, subtitle, and action slot.
 */
interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  badge?: { label: string; color?: string };
}

export function PageHeader({ title, subtitle, actions, badge }: PageHeaderProps) {
  return (
    <div className="h-14 border-b border-soc-border flex items-center justify-between px-6 bg-soc-surface/50 flex-shrink-0">
      <div className="flex items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-semibold text-soc-text">{title}</h1>
            {badge && (
              <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${badge.color || 'bg-soc-primary/20 text-soc-primary'}`}>
                {badge.label}
              </span>
            )}
          </div>
          {subtitle && <p className="text-xs text-soc-text-muted">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
