<#
.SYNOPSIS
    Attribute ShadowStrikePhantomService memory spikes to threads. Task 227.

.DESCRIPTION
    Runs INSIDE the guest. Triggers .NET native-image generation (the workload that
    produced 2-5 GB transient commits on 1.0.117), and every 200 ms samples the
    service's private bytes and per-thread CPU time. Whenever private bytes exceed
    -SpikeMb, the threads that consumed CPU since the previous sample are recorded
    with their description (SetThreadDescription) and start address, so the
    allocation can be traced to a component and, through the PDB, to a function.
#>
param([int]$Seconds = 240, [int]$SpikeMb = 1500, [string]$Out = 'C:\ProgramData\ss-vm\spike.txt')

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class SsThr {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenThread(uint access, bool inherit, uint id);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern int GetThreadDescription(IntPtr h, out IntPtr desc);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, IntPtr ret);
  public static string Describe(uint tid) {
    IntPtr h = OpenThread(0x0800 | 0x0040, false, tid); // QUERY_LIMITED | QUERY_INFORMATION
    if (h == IntPtr.Zero) return "?";
    try {
      string name = "";
      IntPtr p; if (GetThreadDescription(h, out p) >= 0 && p != IntPtr.Zero) { name = Marshal.PtrToStringUni(p); LocalFree(p); }
      IntPtr start; NtQueryInformationThread(h, 9, out start, IntPtr.Size, IntPtr.Zero); // ThreadQuerySetWin32StartAddress
      return name + " start=0x" + start.ToInt64().ToString("X");
    } finally { CloseHandle(h); }
  }
}
"@

$svc = Get-Process ShadowStrikePhantomService
$base = ($svc.Modules | Where-Object ModuleName -eq 'ShadowStrikePhantomService.exe').BaseAddress.ToInt64()
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("image base=0x{0:X}" -f $base)

$ngen = Start-Process "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\ngen.exe" -ArgumentList 'update','/force' -PassThru -WindowStyle Hidden
$prev = @{}
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
    $p = Get-Process -Id $svc.Id -ErrorAction SilentlyContinue
    if (-not $p) { $lines.Add("service gone"); break }
    $cur = @{}
    foreach ($t in $p.Threads) { try { $cur[$t.Id] = $t.TotalProcessorTime.TotalMilliseconds } catch { } }
    $priv = [int]($p.PrivateMemorySize64 / 1MB)
    if ($priv -ge $SpikeMb) {
        $busy = $cur.Keys | ForEach-Object { [pscustomobject]@{ Tid = $_; Ms = $cur[$_] - ($(if ($prev.ContainsKey($_)) { $prev[$_] } else { $cur[$_] })) } } |
                Where-Object { $_.Ms -gt 0 } | Sort-Object Ms -Descending | Select-Object -First 4
        $desc = ($busy | ForEach-Object { "tid={0} cpu={1:N0}ms [{2}]" -f $_.Tid, $_.Ms, [SsThr]::Describe([uint32]$_.Tid) }) -join ' | '
        $lines.Add(("{0:HH:mm:ss.fff} priv={1} MB  {2}" -f (Get-Date).ToUniversalTime(), $priv, $desc))
    }
    $prev = $cur
    Start-Sleep -Milliseconds 200
}
if (-not $ngen.HasExited) { $lines.Add("ngen still running after $Seconds s") }
$lines | Out-File -Encoding utf8 $Out
"spike samples: " + ($lines.Count - 1)
