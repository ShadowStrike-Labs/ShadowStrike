param(
    [string]$FilePath = "C:\ShadowStrike\ShadowStrike\src\Shared_modules\Core\Engine\QuarantineManager.cpp"
)

# Read file content
$content = Get-Content $FilePath -Raw

# Fix Logger::Info calls
$content = $content -replace 'Logger::Info\("([^"]+)"\);', 'SS_LOG_INFO(L"QuarantineManager", L"$1");'

# Fix Logger::Info calls with {} placeholders (most complex)
$content = $content -replace 'Logger::Info\("([^"]*)\{[^}]*\}([^"]*)",([^)]+)\);', 'SS_LOG_INFO(L"QuarantineManager", L"$1%ls$2",$3);'

# Fix Logger::Error calls
$content = $content -replace 'Logger::Error\("([^"]+)"\);', 'SS_LOG_ERROR(L"QuarantineManager", L"$1");'
$content = $content -replace 'Logger::Error\("([^"]*)\{[^}]*\}([^"]*)",([^)]+)\);', 'SS_LOG_ERROR(L"QuarantineManager", L"$1%ls$2",$3);'

# Fix Logger::Warn calls  
$content = $content -replace 'Logger::Warn\("([^"]+)"\);', 'SS_LOG_WARN(L"QuarantineManager", L"$1");'
$content = $content -replace 'Logger::Warn\("([^"]*)\{[^}]*\}([^"]*)",([^)]+)\);', 'SS_LOG_WARN(L"QuarantineManager", L"$1%ls$2",$3);'

# Write back
Set-Content $FilePath $content -NoNewline

# Count remaining
$remaining = [regex]::Matches($content, 'Logger::(Info|Warn|Error|Debug|Fatal)').Count
Write-Output "Remaining Logger:: calls: $remaining"