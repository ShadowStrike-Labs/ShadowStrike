# Memory watchdog and logger for ShadowStrike host work. Runs detached; costs < 50 MB.
#
# Every 5 s:
#   - headroom = min(available physical memory, free commit)
#   - if headroom < $KillBelowGB: kill every build/test process tree (msbuild, cl, link,
#     phantom-tests, mspdbsrv, vctip) immediately, and log it
#   - if any single one of those processes uses more than $MaxProcessGB private memory: kill it
# Every 15 s: append headroom and the top 10 processes by private memory to the log.
# Stops by itself after $MaxHours, or when C:\ShadowStrike\mem-watch.stop exists.
param(
    [double]$KillBelowGB = 5,
    [double]$MaxProcessGB = 8,
    [int]$MaxHours = 12,
    [string]$Log = 'C:\ShadowStrike\mem-watch.log'
)
$ErrorActionPreference = 'SilentlyContinue'
$stop = 'C:\ShadowStrike\mem-watch.stop'
Remove-Item $stop -ErrorAction SilentlyContinue
$guarded = 'MSBuild', 'cl', 'link', 'phantom-tests', 'mspdbsrv', 'vctip', 'lib'
$end = (Get-Date).AddHours($MaxHours)
"$(Get-Date -Format s) watchdog start pid=$PID killBelow=${KillBelowGB}GB maxProcess=${MaxProcessGB}GB" | Out-File $Log -Append -Encoding ascii
$tick = 0
while ((Get-Date) -lt $end -and -not (Test-Path $stop)) {
    $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $head = [math]::Round([math]::Min($m.AvailableMBytes / 1KB, ([double]$m.CommitLimit - [double]$m.CommittedBytes) / 1GB), 1)
    $procs = @(Get-Process -Name $guarded)
    if ($head -lt $KillBelowGB -and $procs.Count -gt 0) {
        foreach ($p in $procs) { & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null }
        "$(Get-Date -Format s) KILL headroom ${head}GB < ${KillBelowGB}GB: killed $($procs.Count) build/test processes ($(($procs.Name | Sort-Object -Unique) -join ','))" | Out-File $Log -Append -Encoding ascii
    }
    foreach ($p in $procs) {
        if ($p.PrivateMemorySize64 / 1GB -gt $MaxProcessGB) {
            & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null
            "$(Get-Date -Format s) KILL $($p.Name) pid=$($p.Id) private $([math]::Round($p.PrivateMemorySize64/1GB,1))GB > ${MaxProcessGB}GB" | Out-File $Log -Append -Encoding ascii
        }
    }
    if ($tick % 3 -eq 0) {
        $top = Get-Process | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 10 |
            ForEach-Object { "{0}:{1:N1}" -f $_.Name, ($_.PrivateMemorySize64 / 1GB) }
        "$(Get-Date -Format s) head=${head}GB top: $($top -join ' ')" | Out-File $Log -Append -Encoding ascii
    }
    $tick++
    Start-Sleep -Seconds 5
}
"$(Get-Date -Format s) watchdog stop" | Out-File $Log -Append -Encoding ascii
