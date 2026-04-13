/* ============================================================================
 * ShadowStrike Phantom Dashboard — Quarantine Page
 * ============================================================================ */

import { useCallback, useState } from 'react';
import { RotateCcw, Trash2, Shield } from 'lucide-react';
import { PageHeader, Card, Badge, Table, Button, EmptyState } from '@/components/ui';
import { usePolling } from '@/hooks';
import { quarantine as quarantineApi } from '@/api/client';
import type { QuarantineEntry } from '@/types';
import { formatBytes, formatRelativeTime, truncatePath } from '@/utils/format';

function severityVariant(s: string): 'danger' | 'warning' | 'info' | 'success' | 'default' {
  switch (s) {
    case 'critical': return 'danger';
    case 'high':     return 'warning';
    case 'medium':   return 'info';
    case 'low':      return 'success';
    default:         return 'default';
  }
}

export default function QuarantinePage() {
  const fetchQuarantine = useCallback(() => quarantineApi.list(), []);
  const { data: entries, loading, refetch } = usePolling(fetchQuarantine, 15000);

  const [actionLoading, setActionLoading] = useState<string | null>(null);

  async function handleRestore(id: string) {
    setActionLoading(id);
    try {
      await quarantineApi.restore(id);
      refetch();
    } catch {
      // handled
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDelete(id: string) {
    setActionLoading(`del-${id}`);
    try {
      await quarantineApi.remove(id);
      refetch();
    } catch {
      // handled
    } finally {
      setActionLoading(null);
    }
  }

  const columns = [
    {
      key: 'threat',
      header: 'Threat',
      render: (e: QuarantineEntry) => (
        <div>
          <span className="font-medium text-white">{e.threatName}</span>
          <Badge variant={severityVariant(e.severity)} className="ml-2">{e.severity}</Badge>
        </div>
      ),
    },
    {
      key: 'path',
      header: 'Original Path',
      render: (e: QuarantineEntry) => (
        <span className="font-mono text-xs text-gray-400" title={e.originalPath}>
          {truncatePath(e.originalPath, 55)}
        </span>
      ),
    },
    {
      key: 'size',
      header: 'Size',
      render: (e: QuarantineEntry) => (
        <span className="text-xs text-gray-400">{formatBytes(e.fileSize)}</span>
      ),
      className: 'w-24',
    },
    {
      key: 'quarantined',
      header: 'Quarantined',
      render: (e: QuarantineEntry) => (
        <span className="text-xs text-gray-500">{formatRelativeTime(e.quarantinedAt)}</span>
      ),
      className: 'w-32',
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (e: QuarantineEntry) => (
        <div className="flex gap-2">
          {e.canRestore && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void handleRestore(e.id)}
              loading={actionLoading === e.id}
              title="Restore file"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleDelete(e.id)}
            loading={actionLoading === `del-${e.id}`}
            title="Permanently delete"
            className="hover:text-red-400"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      ),
      className: 'w-28',
    },
  ];

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Quarantine"
        description={`${entries?.length ?? 0} item${(entries?.length ?? 0) !== 1 ? 's' : ''} in quarantine`}
      />

      {loading ? (
        <Card className="py-16 text-center text-gray-500">Loading quarantine...</Card>
      ) : (entries?.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Shield className="h-12 w-12" />}
          title="Quarantine is empty"
          description="No threats have been quarantined. Detected threats will appear here."
        />
      ) : (
        <Table
          columns={columns}
          data={entries ?? []}
          keyExtractor={(e) => e.id}
        />
      )}
    </div>
  );
}
