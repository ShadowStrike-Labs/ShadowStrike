/* ============================================================================
 * ShadowStrike Phantom Dashboard — Threats Page
 * ============================================================================ */

import { useCallback, useState } from 'react';
import { AlertTriangle, Search, Filter, ExternalLink } from 'lucide-react';
import { PageHeader, Card, Badge, Table, EmptyState } from '@/components/ui';
import { usePolling, useDebounce } from '@/hooks';
import { threats as threatsApi } from '@/api/client';
import type { ThreatEvent, ThreatSeverity } from '@/types';
import {
  formatRelativeTime,
  truncatePath,
  severityBadge,
  cn,
} from '@/utils/format';

const SEVERITY_ORDER: Record<ThreatSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityVariant(s: ThreatSeverity): 'danger' | 'warning' | 'info' | 'success' | 'default' {
  switch (s) {
    case 'critical': return 'danger';
    case 'high':     return 'warning';
    case 'medium':   return 'info';
    case 'low':      return 'success';
    default:         return 'default';
  }
}

export default function ThreatsPage() {
  const fetchThreats = useCallback(() => threatsApi.list(), []);
  const { data: allThreats, loading } = usePolling(fetchThreats, 10000);

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<ThreatSeverity | 'all'>('all');
  const debouncedSearch = useDebounce(search, 300);

  const filtered = (allThreats ?? [])
    .filter((t) => {
      if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
      if (debouncedSearch) {
        const q = debouncedSearch.toLowerCase();
        return (
          t.threatName.toLowerCase().includes(q) ||
          t.filePath.toLowerCase().includes(q) ||
          t.processName.toLowerCase().includes(q) ||
          t.detectionMethod.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const columns = [
    {
      key: 'severity',
      header: 'Severity',
      render: (t: ThreatEvent) => (
        <Badge variant={severityVariant(t.severity)}>{t.severity}</Badge>
      ),
      className: 'w-24',
    },
    {
      key: 'threat',
      header: 'Threat',
      render: (t: ThreatEvent) => (
        <div>
          <span className="font-medium text-white">{t.threatName}</span>
          <span className="block text-xs text-gray-500">{t.threatCategory} — {t.threatFamily}</span>
        </div>
      ),
    },
    {
      key: 'path',
      header: 'File Path',
      render: (t: ThreatEvent) => (
        <span className="font-mono text-xs text-gray-400" title={t.filePath}>
          {truncatePath(t.filePath, 50)}
        </span>
      ),
    },
    {
      key: 'detection',
      header: 'Detection',
      render: (t: ThreatEvent) => (
        <span className="text-xs text-gray-400">{t.detectionMethod}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (t: ThreatEvent) => (
        <Badge variant={t.actionSuccessful ? 'success' : 'danger'}>{t.action}</Badge>
      ),
    },
    {
      key: 'mitre',
      header: 'MITRE',
      render: (t: ThreatEvent) =>
        t.mitreIds.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {t.mitreIds.slice(0, 2).map((id) => (
              <a
                key={id}
                href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 text-xs text-phantom-400 hover:underline"
              >
                {id}
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            ))}
            {t.mitreIds.length > 2 && (
              <span className="text-xs text-gray-500">+{t.mitreIds.length - 2}</span>
            )}
          </div>
        ) : (
          <span className="text-xs text-gray-600">—</span>
        ),
    },
    {
      key: 'time',
      header: 'Time',
      render: (t: ThreatEvent) => (
        <span className="text-xs text-gray-500">{formatRelativeTime(t.timestamp)}</span>
      ),
      className: 'w-28',
    },
  ];

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Threat Detections"
        description={`${filtered.length} detection${filtered.length !== 1 ? 's' : ''} found`}
      />

      {/* Filters */}
      <Card className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search threats, paths, processes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface py-2 pl-10 pr-4 text-sm text-white placeholder-gray-500 focus:border-phantom-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-500" />
          {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={cn(
                'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                severityFilter === sev
                  ? sev === 'all'
                    ? 'bg-phantom-600/20 text-phantom-400'
                    : severityBadge(sev)
                  : 'text-gray-500 hover:text-gray-300',
              )}
            >
              {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
      </Card>

      {/* Table */}
      {loading ? (
        <Card className="py-16 text-center text-gray-500">Loading threats...</Card>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<AlertTriangle className="h-12 w-12" />}
          title="No threats detected"
          description="Your endpoint is clean. Real-time protection continues to monitor."
        />
      ) : (
        <Table
          columns={columns}
          data={filtered}
          keyExtractor={(t) => t.id}
          emptyMessage="No threats match your filters"
        />
      )}
    </div>
  );
}
