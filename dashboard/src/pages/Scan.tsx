/* ============================================================================
 * ShadowStrike Phantom Dashboard — Scan Page
 * ============================================================================ */

import { useCallback, useState } from 'react';
import { Search, Square, FolderOpen, Zap, HardDrive, Shield } from 'lucide-react';
import { PageHeader, Card, Button, ProgressBar, StatCard, Badge } from '@/components/ui';
import { usePolling } from '@/hooks';
import { scan as scanApi, status as statusApi } from '@/api/client';
import { formatBytes, formatDuration, formatNumber, cn } from '@/utils/format';

export default function ScanPage() {
  const fetchProgress = useCallback(() => scanApi.progress(), []);
  const fetchStats = useCallback(() => statusApi.stats(), []);
  const { data: progress, refetch: refetchProgress } = usePolling(fetchProgress, 2000);
  const { data: stats } = usePolling(fetchStats, 10000);

  const [scanLoading, setScanLoading] = useState<string | null>(null);

  const isScanning = progress?.state === 'SCANNING' || progress?.state === 'QUEUED';

  async function startScan(type: 'quick' | 'full') {
    setScanLoading(type);
    try {
      if (type === 'quick') {
        await scanApi.quick();
      } else {
        await scanApi.full();
      }
      refetchProgress();
    } catch {
      // Error handled by polling
    } finally {
      setScanLoading(null);
    }
  }

  async function stopScan() {
    setScanLoading('stop');
    try {
      await scanApi.stop();
      refetchProgress();
    } catch {
      // handled
    } finally {
      setScanLoading(null);
    }
  }

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Scan"
        description="On-demand malware scanning"
        action={
          isScanning ? (
            <Button variant="danger" onClick={stopScan} loading={scanLoading === 'stop'}>
              <Square className="h-4 w-4" /> Stop Scan
            </Button>
          ) : undefined
        }
      />

      {/* Scan Triggers */}
      {!isScanning && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Card
            className="group cursor-pointer hover:border-phantom-500/50"
            onClick={() => void startScan('quick')}
          >
            <div className="flex items-center gap-4">
              <div className="rounded-xl bg-phantom-600/10 p-3 ring-1 ring-phantom-600/20 group-hover:ring-phantom-500/40 transition-all">
                <Zap className="h-6 w-6 text-phantom-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Quick Scan</h3>
                <p className="text-xs text-gray-500">
                  Scans critical areas — system directories, running processes, startup items
                </p>
              </div>
            </div>
          </Card>

          <Card
            className="group cursor-pointer hover:border-phantom-500/50"
            onClick={() => void startScan('full')}
          >
            <div className="flex items-center gap-4">
              <div className="rounded-xl bg-blue-600/10 p-3 ring-1 ring-blue-600/20 group-hover:ring-blue-500/40 transition-all">
                <HardDrive className="h-6 w-6 text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Full Scan</h3>
                <p className="text-xs text-gray-500">
                  Deep scan of all drives — every file, archive, and memory region
                </p>
              </div>
            </div>
          </Card>

          <Card className="group cursor-pointer hover:border-phantom-500/50">
            <div className="flex items-center gap-4">
              <div className="rounded-xl bg-green-600/10 p-3 ring-1 ring-green-600/20 group-hover:ring-green-500/40 transition-all">
                <FolderOpen className="h-6 w-6 text-green-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Custom Scan</h3>
                <p className="text-xs text-gray-500">
                  Select specific files or directories to scan
                </p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Active Scan Progress */}
      {isScanning && progress && (
        <Card>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 animate-pulse rounded-full bg-phantom-600/20 flex items-center justify-center">
                  <Search className="h-5 w-5 text-phantom-400 animate-pulse" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Scanning...</h3>
                  <span className="text-xs text-gray-400 font-mono truncate block max-w-md">
                    {progress.currentFile || 'Preparing...'}
                  </span>
                </div>
              </div>
              <Badge variant="info">{progress.state}</Badge>
            </div>

            <ProgressBar
              value={progress.percentComplete}
              color="bg-phantom-500"
              showLabel
            />

            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <div className="text-center">
                <div className="text-lg font-bold text-white">
                  {formatNumber(progress.filesScanned)}
                </div>
                <div className="text-xs text-gray-500">Files Scanned</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-white">
                  {formatBytes(progress.bytesScanned)}
                </div>
                <div className="text-xs text-gray-500">Data Processed</div>
              </div>
              <div className="text-center">
                <div className={cn(
                  'text-lg font-bold',
                  progress.threatsFound > 0 ? 'text-red-400' : 'text-green-400',
                )}>
                  {progress.threatsFound}
                </div>
                <div className="text-xs text-gray-500">Threats Found</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-white">
                  {formatDuration(progress.estimatedRemainingMs)}
                </div>
                <div className="text-xs text-gray-500">Estimated Remaining</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Scan History Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Total Scans"
          value={formatNumber(stats?.totalScans ?? 0)}
          icon={<Search className="h-4 w-4" />}
        />
        <StatCard
          label="Files Scanned"
          value={formatNumber(stats?.filesScanned ?? 0)}
          icon={<HardDrive className="h-4 w-4" />}
        />
        <StatCard
          label="Threats Found"
          value={formatNumber(stats?.totalThreats ?? 0)}
          icon={<Shield className="h-4 w-4" />}
        />
        <StatCard
          label="Avg Scan Time"
          value={`${stats?.avgScanTimeMs ?? 0}ms`}
          icon={<Zap className="h-4 w-4" />}
        />
      </div>
    </div>
  );
}
