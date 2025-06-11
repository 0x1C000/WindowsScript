# full_anti_miner_kit_v2.ps1
# FULL ANTI-MINER KIT v2 - Windows 11
# Rimozione alla radice di miner e persistenti
# by 0x1C for user - version EXTREME ROOT

# Setup paths
$logPath = "$env:USERPROFILE\Desktop\full_anti_miner_log_v2.txt"
$taskCsvPath = "$env:USERPROFILE\Desktop\scheduled_tasks_v2.csv"
$servicesCsvPath = "$env:USERPROFILE\Desktop\suspicious_services_v2.csv"

if (Test-Path $logPath) { Remove-Item $logPath -Force }
if (Test-Path $taskCsvPath) { Remove-Item $taskCsvPath -Force }
if (Test-Path $servicesCsvPath) { Remove-Item $servicesCsvPath -Force }

# Suspicious keywords / blacklist
$suspiciousKeywords = @(
    "xmrig", "minerd", "coinhive", "nicehash", "cryptonight", "update.exe", "svc.exe",
    "winupdate.exe", "windowsupdate.exe", "sqlminer", "trojan", "miner", "pools", "stratum",
    "cpuworker", "gpuminer", "kernelminer", "svhost.exe", "sysupdate.exe", "intelupdate.exe",
    "amdservice.exe", "driverupdate.exe", "systemcheck.exe", "msdriver.exe", "driverfix.exe"
)

# Logging helper
function Log {
    param($text)
    Write-Host $text
    Add-Content -Path $logPath -Value $text
}

# Banner
Clear-Host
Write-Host "=============================================" -ForegroundColor Red
Write-Host "           FULL ANTI-MINER KIT v2" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host "Log file: $logPath"
Write-Host "Scheduled Tasks CSV: $taskCsvPath"
Write-Host "Suspicious Services CSV: $servicesCsvPath`n"

# Registry check function
function Check-RegistryKey {
    param($path, $hiveName)
    Log "`n[*] Checking $hiveName\$path"

    try {
        $values = Get-ItemProperty -Path "$hiveName\$path" -ErrorAction Stop | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
        foreach ($property in $values.PSObject.Properties) {
            $valueString = "$($property.Name) = $($property.Value)"
            $highlight = $false
            foreach ($keyword in $suspiciousKeywords) {
                if ($property.Value -match $keyword) {
                    $highlight = $true
                    break
                }
            }
            if ($highlight) {
                Log "  -> [SUSPICIOUS] $valueString"
            } else {
                Log "  -> $valueString"
            }
        }
    } catch {
        Log "  (No values found or key does not exist)"
    }
}

# Scheduled Tasks check and auto-clean
function CheckAndCleanScheduledTasks {
    Log "`n[*] Checking Scheduled Tasks:"
    $tasksInfo = @()

    try {
        $tasks = Get-ScheduledTask
        foreach ($task in $tasks) {
            $definition = (Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath)
            $taskRow = [PSCustomObject]@{
                Path       = "$($task.TaskPath)$($task.TaskName)"
                LastRun    = $definition.LastRunTime
                NextRun    = $definition.NextRunTime
                Suspicious = "No"
            }

            $isSuspicious = $false
            foreach ($keyword in $suspiciousKeywords) {
                if ($task.TaskName -match $keyword -or $task.TaskPath -match $keyword) {
                    $taskRow.Suspicious = "YES"
                    $isSuspicious = $true
                    break
                }
            }

            if ($isSuspicious) {
                Log "  -> [AUTO-REMOVE] $($taskRow.Path)"
                try {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
                    Log "     -> Task REMOVED."
                } catch {
                    Log "     -> Error removing task!"
                }
            } else {
                Log "  -> $($taskRow.Path) | LastRun: $($taskRow.LastRun) | NextRun: $($taskRow.NextRun)"
            }

            $tasksInfo += $taskRow
        }

        $tasksInfo | Export-Csv -Path $taskCsvPath -NoTypeInformation -Encoding UTF8
        Log "`n[*] Scheduled Tasks exported to CSV: $taskCsvPath"

    } catch {
        Log "  (Error reading Scheduled Tasks)"
    }
}

# Services check and auto-clean
function CheckAndCleanServices {
    Log "`n[*] Checking Services:"
    $servicesInfo = @()

    try {
        $services = Get-WmiObject win32_service
        foreach ($service in $services) {
            $serviceRow = [PSCustomObject]@{
                Name        = $service.Name
                DisplayName = $service.DisplayName
                PathName    = $service.PathName
                State       = $service.State
                StartMode   = $service.StartMode
                Suspicious  = "No"
            }

            $isSuspicious = $false
            foreach ($keyword in $suspiciousKeywords) {
                if ($service.PathName -match $keyword -or $service.Name -match $keyword -or $service.DisplayName -match $keyword) {
                    $serviceRow.Suspicious = "YES"
                    $isSuspicious = $true
                    break
                }
            }

            if ($isSuspicious) {
                Log "  -> [AUTO-DISABLE] $($serviceRow.Name) - $($serviceRow.DisplayName)"
                try {
                    Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service.Name -StartupType Disabled
                    Log "     -> Service STOPPED and DISABLED."
                } catch {
                    Log "     -> Error disabling service!"
                }
            } else {
                Log "  -> $($serviceRow.Name) - $($serviceRow.DisplayName)"
            }

            $servicesInfo += $serviceRow
        }

        $servicesInfo | Export-Csv -Path $servicesCsvPath -NoTypeInformation -Encoding UTF8
        Log "`n[*] Suspicious Services exported to CSV: $servicesCsvPath"

    } catch {
        Log "  (Error reading Services)"
    }
}

# Interactive removal of Registry Value
function Remove-RegistryValueInteractive {
    param($path, $hiveName)

    try {
        $values = Get-ItemProperty -Path "$hiveName\$path" -ErrorAction Stop | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
        $counter = 1
        $valMap = @{}
        foreach ($property in $values.PSObject.Properties) {
            Write-Host "$counter. $($property.Name) = $($property.Value)"
            $valMap[$counter] = $property.Name
            $counter++
        }

        $selection = Read-Host "`nEnter the number of the value to delete (or press Enter to skip)"
        if ($selection -ne "") {
            if ($valMap.ContainsKey([int]$selection)) {
                $valueToRemove = $valMap[[int]$selection]
                Remove-ItemProperty -Path "$hiveName\$path" -Name $valueToRemove -Force
                Write-Host "-> Value deleted: $valueToRemove" -ForegroundColor Green
            } else {
                Write-Host "Invalid number." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "No values to delete or key does not exist."
    }
}

# TEMP and AppData scan
function ScanTempAndAppData {
    Log "`n[*] Scanning TEMP and AppData for suspicious files:"
    $folders = @(
        "$env:TEMP",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )

    foreach ($folder in $folders) {
        Log "  -> Scanning $folder ..."
        try {
            Get-ChildItem -Path $folder -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                foreach ($keyword in $suspiciousKeywords) {
                    if ($_.FullName -match $keyword) {
                        Log "    [SUSPICIOUS FILE] $($_.FullName)"
                    }
                }
            }
        } catch {
            Log "  (Error scanning $folder)"
        }
    }
}

# Chrome shortcut scan
function ScanChromeShortcuts {
    Log "`n[*] Scanning Chrome shortcuts (.lnk):"
    $shortcuts = Get-ChildItem "$env:USERPROFILE\Desktop","$env:APPDATA\Microsoft\Windows\Start Menu","$env:ProgramData\Microsoft\Windows\Start Menu" -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue

    foreach ($shortcut in $shortcuts) {
        try {
            $wshShell = New-Object -ComObject WScript.Shell
            $lnk = $wshShell.CreateShortcut($shortcut.FullName)
            if ($lnk.TargetPath -match "chrome.exe") {
                Log "  -> Found Chrome shortcut: $($shortcut.FullName)"
                Log "     Target: $($lnk.TargetPath)"
                Log "     Arguments: $($lnk.Arguments)"
                foreach ($keyword in $suspiciousKeywords) {
                    if ($lnk.Arguments -match $keyword) {
                        Log "    [SUSPICIOUS SHORTCUT ARGUMENT] $($lnk.Arguments)"
                    }
                }
            }
        } catch {
            Log "  (Error reading shortcut $($shortcut.FullName))"
        }
    }
}

# === MAIN ===

# 1. Registry keys
Check-RegistryKey "Software\Microsoft\Windows\CurrentVersion\Run" "HKCU"
Check-RegistryKey "Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKCU"
Check-RegistryKey "Software\Microsoft\Windows\CurrentVersion\Run" "HKLM"
Check-RegistryKey "Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKLM"

# 2. Scheduled Tasks
CheckAndCleanScheduledTasks

# 3. Services
CheckAndCleanServices

# 4. TEMP and AppData scan
ScanTempAndAppData

# 5. Chrome Shortcuts scan
ScanChromeShortcuts

# 6. Registry Run cleanup
Remove-RegistryValueInteractive "Software\Microsoft\Windows\CurrentVersion\Run" "HKCU"
Remove-RegistryValueInteractive "Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKCU"
Remove-RegistryValueInteractive "Software\Microsoft\Windows\CurrentVersion\Run" "HKLM"
Remove-RegistryValueInteractive "Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKLM"

# === END ===
Write-Host "`nFULL ANTI-MINER KIT v2 FINISHED. Check logs and CSV files on Desktop." -ForegroundColor Red
Pause
