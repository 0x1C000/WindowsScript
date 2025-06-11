# chrome_process_scanner.ps1
# Scan all chrome.exe processes and detect suspicious flags / mining behavior
# by 0x1C - for deep chrome analysis

# Suspicious flags / arguments
$suspiciousFlags = @(
    "--headless",
    "--disable-gpu",
    "--disable-sandbox",
    "--no-sandbox",
    "--remote-debugging-port",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-renderer-backgrounding",
    "--force-device-scale-factor"
)

# Suspicious keywords (generic)
$suspiciousKeywords = @(
    "miner", "xmrig", "stratum", "cryptonight", "minerd", "coinhive", "nicehash", "cpuworker", "gpuminer"
)

# Banner
Clear-Host
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "      CHROME PROCESS SCANNER TOOL" -ForegroundColor Yellow
Write-Host "========================================`n"

# Get all chrome.exe processes
$chromeProcesses = Get-WmiObject Win32_Process -Filter "Name='chrome.exe'"

if ($chromeProcesses.Count -eq 0) {
    Write-Host "No chrome.exe processes found." -ForegroundColor Green
    exit
}

# Process each chrome.exe
foreach ($proc in $chromeProcesses) {
    $pid = $proc.ProcessId
    $cmdLine = $proc.CommandLine
    $workingSetMB = [math]::Round($proc.WorkingSetSize / 1MB,2)

    $flagSuspicious = $false
    $keywordSuspicious = $false

    foreach ($flag in $suspiciousFlags) {
        if ($cmdLine -match $flag) {
            $flagSuspicious = $true
            break
        }
    }

    foreach ($keyword in $suspiciousKeywords) {
        if ($cmdLine -match $keyword) {
            $keywordSuspicious = $true
            break
        }
    }

    # Print process info
    Write-Host "----------------------------------------"
    Write-Host "PID: $pid"
    Write-Host "RAM: $workingSetMB MB"
    Write-Host "CommandLine: $cmdLine"

    if ($flagSuspicious -or $keywordSuspicious) {
        Write-Host ">> [SUSPICIOUS PROCESS DETECTED] <<" -ForegroundColor Red
        if ($flagSuspicious) { Write-Host "-> Suspicious FLAG detected." -ForegroundColor Red }
        if ($keywordSuspicious) { Write-Host "-> Suspicious KEYWORD detected." -ForegroundColor Red }
    } else {
        Write-Host "-> Process looks normal." -ForegroundColor Green
    }
}

Write-Host "`nScan complete. If you see SUSPICIOUS PROCESS, consider closing Chrome and scanning system deeper." -ForegroundColor Yellow
Pause
