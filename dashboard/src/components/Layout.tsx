/* ============================================================================
 * ShadowStrike Phantom Dashboard — App Layout (Sidebar + Shell)
 * ============================================================================ */

import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import {
  Shield,
  Activity,
  Search,
  FolderLock,
  AlertTriangle,
  Database,
  Settings,
  BarChart3,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/utils/format';
import { StatusIndicator } from '@/components/ui';
import { usePolling } from '@/hooks';
import { status as statusApi } from '@/api/client';

// ============================================================================
// Navigation Items
// ============================================================================

interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
}

const navigation: NavItem[] = [
  { label: 'Overview',          path: '/',              icon: Shield },
  { label: 'Threats',           path: '/threats',       icon: AlertTriangle },
  { label: 'Scan',              path: '/scan',          icon: Search },
  { label: 'Quarantine',        path: '/quarantine',    icon: FolderLock },
  { label: 'Threat Intel',      path: '/threat-intel',  icon: Database },
  { label: 'Alerts',            path: '/alerts',        icon: Activity },
  { label: 'Reports',           path: '/reports',       icon: BarChart3 },
  { label: 'Settings',          path: '/settings',      icon: Settings },
];

// ============================================================================
// Sidebar
// ============================================================================

function Sidebar() {
  const { data: protectionStatus } = usePolling(statusApi.protection, 10000);

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-border bg-surface">
      {/* Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-border px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-phantom-600">
          <Shield className="h-5 w-5 text-white" />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-bold text-white tracking-wide">PHANTOM</span>
          <span className="text-[10px] font-medium uppercase tracking-widest text-gray-500">
            Endpoint Protection
          </span>
        </div>
      </div>

      {/* Protection status pill */}
      <div className="border-b border-border px-4 py-3">
        <div className="flex items-center gap-2 rounded-lg bg-surface-overlay px-3 py-2">
          <StatusIndicator active={protectionStatus?.state === 'ACTIVE'} />
          <span className="text-xs font-medium text-gray-300">
            {protectionStatus?.state === 'ACTIVE'
              ? 'Protection Active'
              : protectionStatus?.state ?? 'Connecting...'}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <ul className="space-y-0.5">
          {navigation.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-phantom-600/15 text-phantom-400'
                      : 'text-gray-400 hover:bg-surface-overlay hover:text-gray-200',
                  )
                }
              >
                <item.icon className="h-[18px] w-[18px]" />
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-4 py-3">
        <div className="flex items-center gap-2 text-[10px] text-gray-600">
          <Wifi className="h-3 w-3" />
          <span>v{protectionStatus?.version ?? '—'}</span>
          <span className="mx-1">•</span>
          <span>Sigs: {protectionStatus?.signatureVersion ?? '—'}</span>
        </div>
      </div>
    </aside>
  );
}

// ============================================================================
// Layout Shell
// ============================================================================

export default function Layout() {
  return (
    <div className="min-h-screen bg-surface">
      <Sidebar />
      <main className="pl-64">
        <div className="min-h-screen p-6">
          <React.Suspense
            fallback={
              <div className="flex h-64 items-center justify-center">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-phantom-500 border-t-transparent" />
              </div>
            }
          >
            <Outlet />
          </React.Suspense>
        </div>
      </main>
    </div>
  );
}
