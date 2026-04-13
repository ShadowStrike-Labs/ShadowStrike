/* ============================================================================
 * ShadowStrike Phantom Dashboard — Alerts Page
 * ============================================================================ */

import { useCallback, useState } from 'react';
import { Bell, Check, AlertTriangle, Info, AlertCircle } from 'lucide-react';
import { PageHeader, Card, Badge, Button, EmptyState } from '@/components/ui';
import { usePolling } from '@/hooks';
import { alerts as alertsApi } from '@/api/client';
import type { AlertPriority } from '@/types';
import { formatRelativeTime, cn } from '@/utils/format';

function priorityIcon(p: AlertPriority) {
  switch (p) {
    case 'critical': return <AlertCircle className="h-4 w-4 text-red-400" />;
    case 'high':     return <AlertTriangle className="h-4 w-4 text-orange-400" />;
    case 'medium':   return <Info className="h-4 w-4 text-yellow-400" />;
    case 'low':      return <Info className="h-4 w-4 text-blue-400" />;
    default:         return <Info className="h-4 w-4 text-gray-400" />;
  }
}

function priorityVariant(p: AlertPriority): 'danger' | 'warning' | 'info' | 'success' | 'default' {
  switch (p) {
    case 'critical': return 'danger';
    case 'high':     return 'warning';
    case 'medium':   return 'info';
    case 'low':      return 'success';
    default:         return 'default';
  }
}

export default function AlertsPage() {
  const fetchAlerts = useCallback(() => alertsApi.list(), []);
  const { data: allAlerts, loading, refetch } = usePolling(fetchAlerts, 10000);

  const [filter, setFilter] = useState<'all' | 'unack' | 'ack'>('unack');
  const [ackLoading, setAckLoading] = useState<string | null>(null);

  const filtered = (allAlerts ?? []).filter((a) => {
    if (filter === 'unack') return !a.acknowledged;
    if (filter === 'ack') return a.acknowledged;
    return true;
  });

  async function acknowledgeAlert(id: string) {
    setAckLoading(id);
    try {
      await alertsApi.acknowledge(id);
      refetch();
    } catch {
      // handled
    } finally {
      setAckLoading(null);
    }
  }

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Alerts"
        description={`${(allAlerts ?? []).filter(a => !a.acknowledged).length} unacknowledged`}
      />

      {/* Filter tabs */}
      <Card className="flex items-center gap-2">
        {(['unack', 'all', 'ack'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              'rounded-lg px-4 py-2 text-sm font-medium transition-colors',
              filter === f
                ? 'bg-phantom-600/20 text-phantom-400'
                : 'text-gray-500 hover:text-gray-300',
            )}
          >
            {f === 'unack' ? 'Unacknowledged' : f === 'ack' ? 'Acknowledged' : 'All'}
          </button>
        ))}
      </Card>

      {/* Alert list */}
      {loading ? (
        <Card className="py-16 text-center text-gray-500">Loading alerts...</Card>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Bell className="h-12 w-12" />}
          title={filter === 'unack' ? 'No unacknowledged alerts' : 'No alerts'}
          description="You're all caught up."
        />
      ) : (
        <div className="space-y-2">
          {filtered.map((alert) => (
            <Card
              key={alert.id}
              className={cn(
                'flex items-start gap-4 transition-all',
                !alert.acknowledged && 'border-l-2',
                !alert.acknowledged && alert.priority === 'critical' && 'border-l-red-500',
                !alert.acknowledged && alert.priority === 'high' && 'border-l-orange-500',
                !alert.acknowledged && alert.priority === 'medium' && 'border-l-yellow-500',
                !alert.acknowledged && alert.priority === 'low' && 'border-l-blue-500',
              )}
            >
              {priorityIcon(alert.priority)}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'text-sm font-medium',
                    alert.acknowledged ? 'text-gray-400' : 'text-white',
                  )}>
                    {alert.title}
                  </span>
                  <Badge variant={priorityVariant(alert.priority)}>{alert.priority}</Badge>
                  {alert.acknowledged && (
                    <Badge variant="success">Acknowledged</Badge>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-gray-500">{alert.message}</p>
                <div className="mt-1 flex items-center gap-3 text-[10px] text-gray-600">
                  <span>Source: {alert.source}</span>
                  <span>{formatRelativeTime(alert.timestamp)}</span>
                </div>
              </div>
              {!alert.acknowledged && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void acknowledgeAlert(alert.id)}
                  loading={ackLoading === alert.id}
                >
                  <Check className="h-3.5 w-3.5" /> Ack
                </Button>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
