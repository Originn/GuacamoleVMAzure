# hibernation_setup.ps1
# Script to prepare for Azure VM hibernation with ShopFloorEditor running for SolidCAMOperator1
# Updated with Azure-specific hibernation commands

# Script execution logging
$scriptLogPath = "C:\ProgramData\SolidCAM\script_execution_log.txt"
$proofPath = "C:\ProgramData\SolidCAM\script_execution_proofs"
$versionInfo = "v5.0 - Direct Azure Hibernation"

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

Write-Output "=== Preparing VM for hibernation with ShopFloorEditor running for SolidCAMOperator1 ==="

# 1. Ensure hibernation is enabled and set to full
Write-Output "1) Enabling full hibernation..."
# Verify hibernate settings were properly applied
$hibernateResult = powercfg /hibernate on
$hibfileResult = powercfg /h /type full
Add-Content -Path $scriptLogPath -Value "Hibernate enabled: $hibernateResult"
Add-Content -Path $scriptLogPath -Value "HibFile type set: $hibfileResult"
Write-Output "Hibernate results: $hibernateResult, $hibfileResult"

# Create a status file to track hibernation stages
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "setup_initiated" -Force
Add-Content -Path $scriptLogPath -Value "Hibernation stage tracking file created: setup_initiated"

# 2) Configure auto-logon for SolidCAMOperator1 for future startups
Write-Output "2) Configuring AutoAdminLogon for SolidCAMOperator1"
$regResults = @()
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d SolidCAMOperator1 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rt@wqPP7ZvUgtS7 /f
$regResults += reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d . /f
Add-Content -Path $scriptLogPath -Value "Auto-logon registry settings applied"

# Add all SolidCAMOperator accounts to Administrators group
Write-Output "Adding all SolidCAMOperator accounts to Administrators group"
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator1" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator2" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator3" -ErrorAction SilentlyContinue
Add-Content -Path $scriptLogPath -Value "All SolidCAMOperator accounts added to Administrators group"

# 3) Create post-hibernation validation script
Write-Output "3) Creating post-hibernation validation script..."
$validationScriptPath = "C:\ProgramData\SolidCAM\validate_resume.ps1"
$validationScript = @"
# validate_resume.ps1
# Hibernation validation script

Write-Output "=== Post-Hibernation Validation ==="
Write-Output "Checking if ShopFloorEditor maintained its state through hibernation..."

# Create log directory if it doesn't exist
if (!(Test-Path "C:\ProgramData\SolidCAM")) {
    New-Item -Path "C:\ProgramData\SolidCAM" -ItemType Directory -Force | Out-Null
}

# Start validation logging
`$validationLogPath = "C:\ProgramData\SolidCAM\validation_log.txt"
Add-Content -Path `$validationLogPath -Value "$(Get-Date) - Running post-hibernation validation check"

# Get system boot time
`$lastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
`$uptime = (Get-Date) - `$lastBootUpTime
Write-Output "System uptime: `$(`$uptime.Hours) hours, `$(`$uptime.Minutes) minutes, `$(`$uptime.Seconds) seconds"
Add-Content -Path `$validationLogPath -Value "System uptime: `$(`$uptime.Hours) hours, `$(`$uptime.Minutes) minutes, `$(`$uptime.Seconds) seconds"

# Check for ShopFloorEditor process
`$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

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
    
    # Try to start ShopFloorEditor
    try {
        Start-Process -FilePath "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
        Add-Content -Path `$validationLogPath -Value "Attempted to start ShopFloorEditor manually"
        Write-Output "Attempted to start ShopFloorEditor manually"
    } catch {
        Add-Content -Path `$validationLogPath -Value "Failed to start ShopFloorEditor: `$_"
        Write-Output "Failed to start ShopFloorEditor: `$_"
    }
}

# Log validation results
`$logPath = "C:\ProgramData\SolidCAM\hibernation_results.txt"
Add-Content -Path `$logPath -Value "Validation run: `$(Get-Date)"
Add-Content -Path `$logPath -Value "ShopFloorEditor running: `$(`$null -ne `$shopFloorProcess)"
Add-Content -Path `$logPath -Value "Hibernation stage: `$(Get-Content -Path 'C:\ProgramData\SolidCAM\hibernation_stage.txt' -ErrorAction SilentlyContinue)"
Add-Content -Path `$logPath -Value "-----------------------------------"
"@

Set-Content -Path $validationScriptPath -Value $validationScript
Add-Content -Path $scriptLogPath -Value "Created validation script at $validationScriptPath"

# Create scheduled task for validation upon resume
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

# 4) Create startup tasks for all ShopFloorEditor operator accounts
Write-Output "4) Creating ShopFloorEditor startup tasks for all operator accounts..."

# Common startup script for all operators
$startupScript = @"
@echo off
echo Starting ShopFloorEditor startup check at %date% %time% > C:\ProgramData\SolidCAM\startup_log.txt

REM Wait for system to initialize
timeout /t 30 /nobreak

REM Check if ShopFloorEditor is already running
tasklist /FI "IMAGENAME eq ShopFloorEditor.exe" | find "ShopFloorEditor.exe" > nul
if errorlevel 1 (
    echo ShopFloorEditor not running, starting it now >> C:\ProgramData\SolidCAM\startup_log.txt
    start "" "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
) else (
    echo ShopFloorEditor already running >> C:\ProgramData\SolidCAM\startup_log.txt
)
"@

$startupScriptPath = "C:\ProgramData\SolidCAM\start_shopfloor.cmd"
Set-Content -Path $startupScriptPath -Value $startupScript -Force

# Create scheduled tasks for each operator
foreach ($operatorNum in 1..3) {
    $operatorName = "SolidCAMOperator$operatorNum"
    $startupTaskName = "SolidCAM-StartShopFloorEditor-$operatorName"
    
    # Remove existing task if it exists
    $taskExists = Get-ScheduledTask -TaskName $startupTaskName -ErrorAction SilentlyContinue
    if ($taskExists) {
        Unregister-ScheduledTask -TaskName $startupTaskName -Confirm:$false
    }
    
    # Create new task
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$startupScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon -User $operatorName
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $operatorName -LogonType Interactive -RunLevel Highest
    
    Register-ScheduledTask -TaskName $startupTaskName `
                          -Action $action `
                          -Trigger $trigger `
                          -Settings $settings `
                          -Principal $principal `
                          -Force
                          
    Write-Output "Created startup task for $operatorName"
    Add-Content -Path $scriptLogPath -Value "Created scheduled task for $operatorName to start ShopFloorEditor at logon"
}

# Create a system-wide scheduled task as backup
$systemTaskName = "SolidCAM-StartShopFloorEditor-System"
$taskExists = Get-ScheduledTask -TaskName $systemTaskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $systemTaskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$startupScriptPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $systemTaskName `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -Principal $principal `
                       -Force
                       
Write-Output "Created system-wide startup task"
Add-Content -Path $scriptLogPath -Value "Created system-wide scheduled task to start ShopFloorEditor at startup"

# 5) Start ShopFloorEditor now
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
Write-Output "5) Starting ShopFloorEditor..."

if (!(Test-Path $editorPath)) {
    Write-Output "WARNING: ShopFloorEditor executable not found at expected path: $editorPath"
    Add-Content -Path $scriptLogPath -Value "WARNING: ShopFloorEditor executable not found at: $editorPath"
} else {
    Write-Output "ShopFloorEditor found at: $editorPath"
    Add-Content -Path $scriptLogPath -Value "ShopFloorEditor executable found at: $editorPath"
    
    # Check if ShopFloorEditor is already running
    $shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
    
    if ($shopFloorProcess) {
        Write-Output "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
        Add-Content -Path $scriptLogPath -Value "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
    } else {
        Write-Output "Starting ShopFloorEditor process..."
        Add-Content -Path $scriptLogPath -Value "Starting ShopFloorEditor process"
        
        try {
            # Try to start the process directly
            Start-Process -FilePath $editorPath
            Start-Sleep -Seconds 5
            
            # Check if it started successfully
            $shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
            if ($shopFloorProcess) {
                Write-Output "ShopFloorEditor started successfully with PID: $($shopFloorProcess.Id)"
                Add-Content -Path $scriptLogPath -Value "ShopFloorEditor started successfully with PID: $($shopFloorProcess.Id)"
            } else {
                Write-Output "Failed to start ShopFloorEditor directly. Trying alternative methods..."
                Add-Content -Path $scriptLogPath -Value "Failed to start ShopFloorEditor directly, trying alternatives"
                
                # Create a scheduled task to run immediately
                $immediateTaskName = "SolidCAM-StartShopFloorNow-$(Get-Random)"
                $action = New-ScheduledTaskAction -Execute $editorPath
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType Interactive -RunLevel Highest
                
                Register-ScheduledTask -TaskName $immediateTaskName `
                                      -Action $action `
                                      -Trigger $trigger `
                                      -Principal $principal `
                                      -Force
                
                Write-Output "Created immediate task to start ShopFloorEditor"
                Add-Content -Path $scriptLogPath -Value "Created immediate task to start ShopFloorEditor"
                
                # Wait for it to run
                Start-Sleep -Seconds 15
                
                # Clean up the task
                Unregister-ScheduledTask -TaskName $immediateTaskName -Confirm:$false
            }
        } catch {
            Write-Output "Error starting ShopFloorEditor: $_"
            Add-Content -Path $scriptLogPath -Value "Error starting ShopFloorEditor: $_"
        }
    }
}

# 6) Wait for ShopFloorEditor to initialize
Write-Output "6) Waiting for ShopFloorEditor to initialize (30 seconds)..."
Add-Content -Path $scriptLogPath -Value "Waiting for ShopFloorEditor to initialize (30 seconds)"
Start-Sleep -Seconds 30

# Verify the application is running
$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
if ($shopFloorProcess) {
    Write-Output "ShopFloorEditor is running with PID: $($shopFloorProcess.Id)"
    Add-Content -Path $scriptLogPath -Value "ShopFloorEditor is running with PID: $($shopFloorProcess.Id)"
    
    # Get the session ID
    $sessionId = (Get-Process -Id $shopFloorProcess.Id).SessionId
    Write-Output "ShopFloorEditor is running in Session ID: $sessionId"
    Add-Content -Path $scriptLogPath -Value "ShopFloorEditor is running in Session ID: $sessionId"
} else {
    Write-Output "WARNING: ShopFloorEditor does not appear to be running after wait period"
    Add-Content -Path $scriptLogPath -Value "WARNING: ShopFloorEditor does not appear to be running after wait period"
}

# 7) Update stage tracker
Set-Content -Path "C:\ProgramData\SolidCAM\hibernation_stage.txt" -Value "ready_for_hibernate" -Force
Add-Content -Path $scriptLogPath -Value "Updated hibernation stage to: ready_for_hibernate"

# Log script execution end
$endTime = Get-Date
$executionTime = $endTime - $startTime
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - hibernation_setup.ps1 completed in $($executionTime.TotalSeconds) seconds"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\hibernation_setup_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
Version: $versionInfo
ShopFloorEditor started, ready for hibernation command from Azure portal or API
All required startup tasks created for post-hibernation operation"

# 8) No direct hibernation command here - the Azure Function should use the Azure API
Write-Output "========================================================================="
Write-Output "IMPORTANT: ShopFloorEditor is now running and ready for hibernation."
Write-Output "The VM must now be hibernated using the Azure API:"
Write-Output "   Stop-AzVM -ResourceGroupName '<resource-group>' -Name '<vm-name>' -HibernateVM"
Write-Output "This should be triggered by the Azure Function controlling this VM."
Write-Output "========================================================================="

# Set exit code to indicate completion
exit 0