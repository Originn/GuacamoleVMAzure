# validate_hibernation.ps1
# Script to validate that application state was preserved across hibernation

# Script execution logging
$scriptLogPath = "C:\ProgramData\SolidCAM\script_execution_log.txt"
$proofPath = "C:\ProgramData\SolidCAM\script_execution_proofs"

# Create directories if they don't exist
if (!(Test-Path (Split-Path -Parent $scriptLogPath))) {
    New-Item -Path (Split-Path -Parent $scriptLogPath) -ItemType Directory -Force | Out-Null
}
if (!(Test-Path $proofPath)) {
    New-Item -Path $proofPath -ItemType Directory -Force | Out-Null
}

# Log script execution start
$startTime = Get-Date
Add-Content -Path $scriptLogPath -Value "Script execution: $startTime - validate_hibernation.ps1 starting"
Write-Output "=== SCRIPT-ID: validate_hibernation.ps1 starting execution at $startTime ==="

# Script to validate that application state was preserved across hibernation

Write-Output "=== Validating VM hibernation state restoration ==="
Write-Output "Date/Time: $(Get-Date)"

# 1. Check if we've resumed from hibernation
Write-Output "1) Checking if VM resumed from hibernation..."
$lastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$currentTime = Get-Date
$uptime = $currentTime - $lastBootUpTime

Write-Output "   Current system uptime: $($uptime.Hours) hours, $($uptime.Minutes) minutes, $($uptime.Seconds) seconds"

# Get power transition events from the event log
$hibernateEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 1, 42 # 1 = system startup, 42 = system resume from hibernate
} -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-1) }

$resumedFromHibernate = $false
foreach ($event in $hibernateEvents) {
    if ($event.Id -eq 42) { # Resume from hibernate
        Write-Output "   Found hibernate resume event at: $($event.TimeCreated)"
        $resumedFromHibernate = $true
        break
    }
}

if ($resumedFromHibernate) {
    Write-Output "   VM has resumed from hibernation!"
} else {
    Write-Output "   No evidence found that the VM resumed from hibernation."
    Write-Output "   This might be a normal startup or the events might have been cleared."
}

# 2. Check if ShopFloorEditor is running
Write-Output "2) Checking if ShopFloorEditor maintained its state..."
$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

if ($shopFloorProcess) {
    Write-Output "   SUCCESS: ShopFloorEditor is running with PID: $($shopFloorProcess.Id)"
    Write-Output "   Process start time: $($shopFloorProcess.StartTime)"
    
    # Calculate process uptime
    $processUptime = $currentTime - $shopFloorProcess.StartTime
    Write-Output "   Process running for: $($processUptime.Hours) hours, $($processUptime.Minutes) minutes, $($processUptime.Seconds) seconds"
    
    # Compare with system uptime
    if ($processUptime.TotalSeconds -gt $uptime.TotalSeconds) {
        Write-Output "   CONFIRMED: Process start time predates system boot time!"
        Write-Output "   This is strong evidence that hibernation successfully preserved the application state."
    } else {
        Write-Output "   NOTE: Process was started after system boot."
        Write-Output "   This suggests the process may have been restarted rather than resumed from hibernation."
    }
} else {
    Write-Output "   WARNING: ShopFloorEditor is not running!"
    Write-Output "   This may indicate hibernation did not preserve the application state."
    
    # Check if it's in the list of running processes with a different name
    Write-Output "   Checking for processes that might be ShopFloorEditor under a different name..."
    $processes = Get-Process | Where-Object { 
        $_.Path -like "*SolidCAM*" -or $_.Path -like "*ShopFloor*" 
    } | Select-Object Name, Id, Path, StartTime
    
    if ($processes.Count -gt 0) {
        Write-Output "   Found possible related processes:"
        foreach ($proc in $processes) {
            Write-Output "     - $($proc.Name) (PID: $($proc.Id), Path: $($proc.Path), Started: $($proc.StartTime))"
        }
    } else {
        Write-Output "   No related processes found."
    }
}

# 3. Log the validation results for future reference
$logPath = "C:\ProgramData\SolidCAM\hibernation_validation_log.txt"
$logDir = Split-Path -Parent $logPath

if (!(Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

$logContent = @"
===============================
Hibernation Validation Log
Date/Time: $(Get-Date)
===============================
System Boot Time: $lastBootUpTime
System Uptime: $($uptime.Hours) hours, $($uptime.Minutes) minutes, $($uptime.Seconds) seconds
Resumed From Hibernation: $resumedFromHibernate
ShopFloorEditor Running: $($null -ne $shopFloorProcess)
"@

if ($shopFloorProcess) {
    $logContent += @"

ShopFloorEditor PID: $($shopFloorProcess.Id)
ShopFloorEditor Start Time: $($shopFloorProcess.StartTime)
Process Uptime: $($processUptime.Hours) hours, $($processUptime.Minutes) minutes, $($processUptime.Seconds) seconds
State Preserved: $($processUptime.TotalSeconds -gt $uptime.TotalSeconds)
"@
}

Add-Content -Path $logPath -Value $logContent

Write-Output "3) Validation results logged to: $logPath"
Write-Output "3) Validation results logged to: $logPath"
Write-Output "=== Hibernation validation completed ==="

# Log script execution end
$endTime = Get-Date
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - validate_hibernation.ps1 completed"
Write-Output "=== SCRIPT-ID: validate_hibernation.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\validate_hibernation_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
Hibernation validation results: Resumed From Hibernation: $resumedFromHibernate, ShopFloorEditor Running: $($null -ne $shopFloorProcess)"