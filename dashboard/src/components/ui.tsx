/* ============================================================================
 * ShadowStrike Phantom Dashboard — Reusable UI Components
 * ============================================================================ */

import React from 'react';
import { cn } from '@/utils/format';

// ============================================================================
// Card
// ============================================================================

interface CardProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

export function Card({ children, className, onClick }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-xl border border-border bg-surface-raised p-5 transition-colors',
        onClick && 'cursor-pointer hover:border-border-focus/50',
        className,
      )}
      onClick={onClick}
    >
      {children}
    </div>
  );
}

// ============================================================================
// StatCard — Compact metric display
// ============================================================================

interface StatCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  icon?: React.ReactNode;
  trend?: { value: number; positive: boolean };
  className?: string;
}

export function StatCard({ label, value, sublabel, icon, trend, className }: StatCardProps) {
  return (
    <Card className={cn('flex flex-col gap-2', className)}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-gray-400">
          {label}
        </span>
        {icon && <span className="text-gray-500">{icon}</span>}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold text-white">{value}</span>
        {trend && (
          <span
            className={cn(
              'text-xs font-medium',
              trend.positive ? 'text-green-400' : 'text-red-400',
            )}
          >
            {trend.positive ? '↑' : '↓'} {Math.abs(trend.value)}%
          </span>
        )}
      </div>
      {sublabel && (
        <span className="text-xs text-gray-500">{sublabel}</span>
      )}
    </Card>
  );
}

// ============================================================================
// Badge
// ============================================================================

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  className?: string;
}

const badgeVariants: Record<string, string> = {
  default: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  success: 'bg-green-500/20 text-green-400 border-green-500/30',
  warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  danger:  'bg-red-500/20 text-red-400 border-red-500/30',
  info:    'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium',
        badgeVariants[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}

// ============================================================================
// Button
// ============================================================================

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

const buttonVariants: Record<string, string> = {
  primary:   'bg-phantom-600 hover:bg-phantom-700 text-white border-phantom-500/50',
  secondary: 'bg-surface-overlay hover:bg-surface-subtle text-gray-200 border-border',
  danger:    'bg-red-600/20 hover:bg-red-600/30 text-red-400 border-red-500/30',
  ghost:     'bg-transparent hover:bg-surface-overlay text-gray-300 border-transparent',
};

const buttonSizes: Record<string, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-2.5 text-base',
};

export function Button({
  variant = 'primary',
  size = 'md',
  loading,
  disabled,
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-lg border font-medium',
        'transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-phantom-500/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}

// ============================================================================
// ProgressBar
// ============================================================================

interface ProgressBarProps {
  value: number;
  max?: number;
  className?: string;
  color?: string;
  showLabel?: boolean;
}

export function ProgressBar({
  value,
  max = 100,
  className,
  color = 'bg-phantom-500',
  showLabel,
}: ProgressBarProps) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className={cn('flex items-center gap-3', className)}>
      <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-surface-subtle">
        <div
          className={cn('absolute inset-y-0 left-0 rounded-full transition-all duration-500', color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      {showLabel && (
        <span className="text-xs font-mono text-gray-400">{pct.toFixed(1)}%</span>
      )}
    </div>
  );
}

// ============================================================================
// StatusIndicator — Pulsing dot
// ============================================================================

interface StatusIndicatorProps {
  active: boolean;
  label?: string;
  className?: string;
}

export function StatusIndicator({ active, label, className }: StatusIndicatorProps) {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="relative flex h-2.5 w-2.5">
        {active && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
        )}
        <span
          className={cn(
            'relative inline-flex h-2.5 w-2.5 rounded-full',
            active ? 'bg-green-500' : 'bg-gray-500',
          )}
        />
      </span>
      {label && (
        <span className={cn('text-sm', active ? 'text-green-400' : 'text-gray-500')}>
          {label}
        </span>
      )}
    </div>
  );
}

// ============================================================================
// EmptyState
// ============================================================================

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {icon && <div className="mb-4 text-gray-500">{icon}</div>}
      <h3 className="text-lg font-medium text-gray-300">{title}</h3>
      {description && <p className="mt-1 text-sm text-gray-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

// ============================================================================
// Spinner
// ============================================================================

export function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn('h-6 w-6 animate-spin text-phantom-500', className)}
      viewBox="0 0 24 24"
      fill="none"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

// ============================================================================
// PageHeader
// ============================================================================

interface PageHeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <div className="mb-6 flex items-start justify-between">
      <div>
        <h1 className="text-2xl font-bold text-white">{title}</h1>
        {description && (
          <p className="mt-1 text-sm text-gray-400">{description}</p>
        )}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}

// ============================================================================
// Table
// ============================================================================

interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  className?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T) => string;
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  emptyMessage = 'No data',
}: TableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface-raised p-8 text-center text-gray-500">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border bg-surface-overlay">
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  'px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400',
                  col.className,
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/50">
          {data.map((row) => (
            <tr
              key={keyExtractor(row)}
              className={cn(
                'bg-surface-raised transition-colors',
                onRowClick && 'cursor-pointer hover:bg-surface-overlay',
              )}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((col) => (
                <td key={col.key} className={cn('px-4 py-3 text-sm', col.className)}>
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
