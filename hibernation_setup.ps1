# hibernation_setup.ps1
# Script to prepare for Azure VM hibernation with ShopFloorEditor running for SolidCAMOperator1
# Updated to ensure application runs in Session 1 before hibernation

# Script execution logging
$scriptLogPath = "C:\ProgramData\SolidCAM\script_execution_log.txt"
$proofPath = "C:\ProgramData\SolidCAM\script_execution_proofs"
$versionInfo = "v4.0 - Session 1 Direct Hibernation"

# Create directories if they don't exist
if (!(Test-Path (Split-Path -Parent $scriptLogPath))) {
    New-Item -Path (Split-Path -Parent $scriptLogPath) -ItemType Directory -Force | Out-Null
}
if (!(Test-Path $proofPath)) {
    New-Item -Path $proofPath -ItemType Directory -Force | Out-Null
}

# Log script execution start
$startTime = Get-Date
Add-Content -Path $scriptLogPath -Value "Script execution: $startTime - hibernation_setup.ps1 $versionInfo starting"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 $versionInfo starting execution at $startTime ==="

Write-Output "=== Preparing VM for hibernation with ShopFloorEditor running for SolidCAMOperator1 in Session 1 ==="

# 1. Ensure hibernation is enabled and set to full
Write-Output "1) Enabling full hibernation..."
# Verify hibernate settings were properly applied
$hibernateResult = powercfg /hibernate on
$hibfileResult = powercfg /h /type full
Add-Content -Path $scriptLogPath -Value "Hibernate enabled: $hibernateResult"
Add-Content -Path $scriptLogPath -Value "HibFile type set: $hibfileResult"
Write-Output "Hibernate results: $hibernateResult, $hibfileResult"

# 2) Configure auto-logon for SolidCAMOperator1
Write-Output "2) Configuring AutoAdminLogon for SolidCAMOperator1"
$regResults = @()
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d SolidCAMOperator1 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rt@wqPP7ZvUgtS7 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d . /f
Add-Content -Path $scriptLogPath -Value "Auto-logon registry settings applied for SolidCAMOperator1"

# Create a status file to track hibernation stages
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "setup_initiated" -Force
Add-Content -Path $scriptLogPath -Value "Hibernation stage tracking file created: setup_initiated"

# 3) Create finalize hibernation script for session 1
Write-Output "3) Creating finalize hibernation script for Session 1..."
$finalizeScript = @'
# finalize_hibernate.ps1
# This script runs ShopFloorEditor in Session 1 and then hibernates the system

# Create log directory if it doesn't exist
if (!(Test-Path "C:\ProgramData\SolidCAM")) {
    New-Item -Path "C:\ProgramData\SolidCAM" -ItemType Directory -Force | Out-Null
}

# Start logging
$logFile = "C:\ProgramData\SolidCAM\finalize_hibernate_log.txt"
Add-Content -Path $logFile -Value "$(Get-Date) - Finalize hibernate script starting in Session 1"

# Update stage tracker
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "finalize_started" -Force

# Check if we're in Session 1
$currentSessionId = (Get-Process -Id $PID).SessionId
Add-Content -Path $logFile -Value "$(Get-Date) - Current session ID: $currentSessionId"

# 1. Start ShopFloorEditor
Add-Content -Path $logFile -Value "$(Get-Date) - Starting ShopFloorEditor"
try {
    Start-Process -FilePath "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
    Add-Content -Path $logFile -Value "$(Get-Date) - ShopFloorEditor process started"
    
    # Wait for process to initialize
    Start-Sleep -Seconds 5
    
    # Verify process is running
    $process = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
    if ($process) {
        Add-Content -Path $logFile -Value "$(Get-Date) - Confirmed ShopFloorEditor is running with PID: $($process.Id)"
    } else {
        Add-Content -Path $logFile -Value "$(Get-Date) - WARNING: Could not confirm ShopFloorEditor is running"
    }
} catch {
    Add-Content -Path $logFile -Value "$(Get-Date) - ERROR starting ShopFloorEditor: $_"
}

# 2. Wait to ensure app is fully initialized
Add-Content -Path $logFile -Value "$(Get-Date) - Waiting 30 seconds for application to initialize..."
Start-Sleep -Seconds 30

# Update stage tracker
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "app_started" -Force

# 3. Create backup hibernation task in case immediate hibernation fails
Add-Content -Path $logFile -Value "$(Get-Date) - Creating backup hibernation task"
try {
    $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/h"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Remove task if it already exists
    Unregister-ScheduledTask -TaskName "SolidCAM-FallbackHibernate" -Confirm:$false -ErrorAction SilentlyContinue
    
    # Create the task
    Register-ScheduledTask -TaskName "SolidCAM-FallbackHibernate" `
                          -Action $action `
                          -Trigger $trigger `
                          -Settings $settings `
                          -Principal $principal `
                          -Force

    Add-Content -Path $logFile -Value "$(Get-Date) - Backup hibernation task created successfully"
} catch {
    Add-Content -Path $logFile -Value "$(Get-Date) - ERROR creating backup hibernation task: $_"
    
    # Fallback to simpler task creation
    try {
        schtasks /create /tn "SolidCAM-FallbackHibernate" /tr "shutdown /h" /sc once /st (Get-Date).AddMinutes(2).ToString("HH:mm") /ru "SYSTEM" /f
        Add-Content -Path $logFile -Value "$(Get-Date) - Backup task created using schtasks command"
    } catch {
        Add-Content -Path $logFile -Value "$(Get-Date) - ERROR: Fallback task creation also failed: $_"
    }
}

# Update stage tracker before hibernation
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "ready_for_hibernate" -Force
Add-Content -Path $logFile -Value "$(Get-Date) - Ready to hibernate the system"

# 4. Hibernate the system
Add-Content -Path $logFile -Value "$(Get-Date) - Initiating system hibernation..."

# Wait for any pending disk operations to complete
Start-Sleep -Seconds 5

# Use PowerCfg method for a more reliable hibernation
try {
    # Attempt hibernation using both methods for reliability
    & powercfg /hibernate
    Add-Content -Path $logFile -Value "$(Get-Date) - PowerCfg hibernation command sent"
    
    # If we're still running after powercfg, try shutdown command
    Start-Sleep -Seconds 5
    Add-Content -Path $logFile -Value "$(Get-Date) - System still running, trying shutdown command..."
    shutdown /h
} catch {
    Add-Content -Path $logFile -Value "$(Get-Date) - ERROR during hibernation: $_"
    Add-Content -Path $logFile -Value "$(Get-Date) - Relying on fallback task for hibernation"
}

# We shouldn't get here, but just in case
Add-Content -Path $logFile -Value "$(Get-Date) - Script completed but system still running"
'@

$scriptPath = "C:\ProgramData\SolidCAM\finalize_hibernate.ps1"
Set-Content -Path $scriptPath -Value $finalizeScript -Force
Add-Content -Path $scriptLogPath -Value "Created finalize hibernation script at $scriptPath"

# 4) Create a post-hibernation validation script
Write-Output "4) Creating post-hibernation validation script..."
$validationScriptPath = "C:\ProgramData\SolidCAM\validate_resume.ps1"
$validationScript = @"
# validate_resume.ps1
# FSLogix-aware hibernation validation script

Write-Output "=== Post-Hibernation Validation ==="
Write-Output "Checking if ShopFloorEditor maintained its state through hibernation..."

# Get system boot time
`$lastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
`$uptime = (Get-Date) - `$lastBootUpTime
Write-Output "System uptime: `$(`$uptime.Hours) hours, `$(`$uptime.Minutes) minutes, `$(`$uptime.Seconds) seconds"

# Check for ShopFloorEditor process
`$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

# Log validation check
`$validationLogPath = "C:\ProgramData\SolidCAM\validation_log.txt"
Add-Content -Path `$validationLogPath -Value "$(Get-Date) - Running validation check"
Add-Content -Path `$validationLogPath -Value "System uptime: `$(`$uptime.Hours) hours, `$(`$uptime.Minutes) minutes, `$(`$uptime.Seconds) seconds"

if (`$shopFloorProcess) {
    Write-Output "SUCCESS: ShopFloorEditor is running with PID: `$(`$shopFloorProcess.Id)"
    Add-Content -Path `$validationLogPath -Value "ShopFloorEditor is running with PID: `$(`$shopFloorProcess.Id)"
    
    try {
        # Get session ID
        `$sessionId = (Get-Process -Id `$shopFloorProcess.Id).SessionId
        Write-Output "Process is running in Session ID: `$sessionId"
        Add-Content -Path `$validationLogPath -Value "Process is running in Session ID: `$sessionId"
        
        Write-Output "Process start time: `$(`$shopFloorProcess.StartTime)"
        Add-Content -Path `$validationLogPath -Value "Process start time: `$(`$shopFloorProcess.StartTime)"
        
        # Compare process start time with system boot time
        `$processUptime = (Get-Date) - `$shopFloorProcess.StartTime
        
        if (`$processUptime.TotalSeconds -gt `$uptime.TotalSeconds) {
            Write-Output "CONFIRMED: Process start time predates system boot time!"
            Write-Output "This confirms the application state was preserved through hibernation."
            Add-Content -Path `$validationLogPath -Value "CONFIRMED: Application state preserved through hibernation"
        } else {
            Write-Output "NOTE: Process appears to have been started after system boot."
            Write-Output "Application state may not have been preserved through hibernation, but auto-start worked."
            Add-Content -Path `$validationLogPath -Value "Application was restarted after boot, not preserved"
        }
    } catch {
        Write-Output "Could not determine process start time: `$_"
        Add-Content -Path `$validationLogPath -Value "Error determining process start time: `$_"
    }
} else {
    Write-Output "ShopFloorEditor is not running after hibernation."
    Add-Content -Path `$validationLogPath -Value "ShopFloorEditor is NOT running"
    
    # Try to start it
    try {
        Start-Process -FilePath "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
        Add-Content -Path `$validationLogPath -Value "Attempted to start ShopFloorEditor manually"
        Write-Output "Attempted to start ShopFloorEditor manually"
    } catch {
        Add-Content -Path `$validationLogPath -Value "Failed to start ShopFloorEditor: `$_"
        Write-Output "Failed to start ShopFloorEditor: `$_"
    }
}

# Log the results
`$logPath = "C:\ProgramData\SolidCAM\hibernation_results.txt"
Add-Content -Path `$logPath -Value "Validation run: `$(Get-Date)"
Add-Content -Path `$logPath -Value "ShopFloorEditor running: `$(`$null -ne `$shopFloorProcess)"
Add-Content -Path `$logPath -Value "Hibernation stage: `$(Get-Content -Path 'C:\ProgramData\SolidCAM\hibernation_stage.txt' -ErrorAction SilentlyContinue)"
Add-Content -Path `$logPath -Value "-----------------------------------"
"@

Set-Content -Path $validationScriptPath -Value $validationScript
Add-Content -Path $scriptLogPath -Value "Created validation script at $validationScriptPath"

# Create startup task for validation
Write-Output "Creating startup task to validate hibernation on resume..."
$validateTaskName = "SolidCAM-ValidateHibernation"
$taskExists = Get-ScheduledTask -TaskName $validateTaskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $validateTaskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $validationScriptPath"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $validateTaskName `
                      -Action $action `
                      -Trigger $trigger `
                      -Settings $settings `
                      -Principal $principal `
                      -Force

# 5) Create RunOnce registry entry for auto-logon session 1
Write-Output "5) Setting up RunOnce for SolidCAMOperator1 in Session 1..."

# Check current sessions
Write-Output "Checking current sessions..."
$sessionInfo = query session
Add-Content -Path $scriptLogPath -Value "Current sessions: $sessionInfo"
Write-Output $sessionInfo

# Create a logon script to be triggered on Session 1
$session1CheckScript = @"
@echo off
echo Starting Session 1 check at %date% %time% > C:\ProgramData\SolidCAM\session1_check.log

REM Check current session ID
for /f "tokens=2 delims=:" %%a in ('query session ^| find /i "console"') do set SESSION_ID=%%a
echo Current console session ID: %SESSION_ID% >> C:\ProgramData\SolidCAM\session1_check.log

REM See if ShopFloorEditor is running
tasklist /FI "IMAGENAME eq ShopFloorEditor.exe" | find "ShopFloorEditor.exe" > nul
if errorlevel 1 (
    echo ShopFloorEditor not running, starting it now >> C:\ProgramData\SolidCAM\session1_check.log
    start "" "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
) else (
    echo ShopFloorEditor already running >> C:\ProgramData\SolidCAM\session1_check.log
)

REM Wait for application to initialize
timeout /t 30 /nobreak

REM Hibernate the system
echo Hibernating system >> C:\ProgramData\SolidCAM\session1_check.log
shutdown /h
"@

$session1ScriptPath = "C:\ProgramData\SolidCAM\session1_check.cmd"
Set-Content -Path $session1ScriptPath -Value $session1CheckScript -Force
Add-Content -Path $scriptLogPath -Value "Created Session 1 check script at $session1ScriptPath"

# Add to RunOnce registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v SessionCheck /t REG_SZ /d "cmd.exe /c $session1ScriptPath" /f
Add-Content -Path $scriptLogPath -Value "Added RunOnce registry entry for Session 1 check script"

# 6) Force the restart to run in Session 1
Write-Output "6) Restarting system to run in Session 1 with auto-logon..."

# Log script execution end
$endTime = Get-Date
$executionTime = $endTime - $startTime
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - hibernation_setup.ps1 completed in $($executionTime.TotalSeconds) seconds"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\hibernation_setup_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
Version: $versionInfo
Setup completed - will restart to Session 1 and then hibernate"

# Restart the system to trigger auto-logon in Session 1
Write-Output "Restarting now to trigger Session 1 execution..."
shutdown /r /t 5 /f