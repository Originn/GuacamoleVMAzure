# hibernation_setup.ps1
# Script to prepare for Azure VM hibernation with ShopFloorEditor running for SolidCAMOperator1
# Updated to work with FSLogix profile management

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
Add-Content -Path $scriptLogPath -Value "Script execution: $startTime - hibernation_setup.ps1 starting"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 starting execution at $startTime ==="

Write-Output "=== Preparing VM for hibernation with ShopFloorEditor running for SolidCAMOperator1 ==="

# 1. Ensure hibernation is enabled and set to full
Write-Output "1) Enabling full hibernation..."
powercfg /hibernate on
powercfg /h /type full

# 2. Configure auto-login and auto-start mechanisms compatible with FSLogix
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
Write-Output "2) Checking if ShopFloorEditor is running for SolidCAMOperator1..."

# Check if ShopFloorEditor is already running
$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

if ($shopFloorProcess) {
    Write-Output "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
    
    # Try to check which user is running the process
    try {
        $processOwner = (Get-WmiObject -Query "Select * From Win32_Process Where ProcessId = $($shopFloorProcess.Id)").GetOwner()
        Write-Output "Process is running under user: $($processOwner.Domain)\$($processOwner.User)"
    } catch {
        Write-Output "Could not determine process owner: $_"
    }
} else {
    Write-Output "ShopFloorEditor is not running. Setting up FSLogix-aware auto-start mechanisms..."
    
    # Create startup scripts directory
    $scriptDir = "C:\ProgramData\SolidCAM\StartupScripts"
    if (!(Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
    }
    
    # 1. Create a system startup script that runs before FSLogix profile mount
    try {
        $systemStartupScript = @"
@echo off
echo Starting SolidCAM pre-FSLogix setup at %date% %time% > C:\ProgramData\SolidCAM\fslogix_startup.log

REM Configure auto-logon
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d SolidCAMOperator1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rt@wqPP7ZvUgtS7 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d . /f

REM Create a global startup shortcut for all users
if not exist "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" mkdir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

echo Set oWS = WScript.CreateObject("WScript.Shell") > "C:\ProgramData\SolidCAM\create_shortcut.vbs"
echo sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ShopFloorEditor.lnk" >> "C:\ProgramData\SolidCAM\create_shortcut.vbs" 
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "C:\ProgramData\SolidCAM\create_shortcut.vbs"
echo oLink.TargetPath = "$editorPath" >> "C:\ProgramData\SolidCAM\create_shortcut.vbs"
echo oLink.Save >> "C:\ProgramData\SolidCAM\create_shortcut.vbs"

cscript //nologo "C:\ProgramData\SolidCAM\create_shortcut.vbs"

REM Modify FSLogix settings if needed for our application
REM (This section can be expanded based on specific FSLogix configuration requirements)

echo Pre-FSLogix setup completed at %date% %time% >> C:\ProgramData\SolidCAM\fslogix_startup.log
"@
        
        $startupScriptPath = "$scriptDir\PreFSLogixSetup.cmd"
        Set-Content -Path $startupScriptPath -Value $systemStartupScript -Force
        
        # Create a scheduled task to run at system startup
        $startupTaskName = "SolidCAM-PreFSLogixSetup"
        
        # Check if task exists and remove if it does
        $taskExists = Get-ScheduledTask -TaskName $startupTaskName -ErrorAction SilentlyContinue
        if ($taskExists) {
            Unregister-ScheduledTask -TaskName $startupTaskName -Confirm:$false
        }
        
        # Create new task
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$startupScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName $startupTaskName `
                               -Action $action `
                               -Trigger $trigger `
                               -Settings $settings `
                               -Principal $principal `
                               -Force
        
        Write-Output "Pre-FSLogix startup task created successfully"
    } catch {
        Write-Output "Error creating pre-FSLogix startup task: $_"
        
        # Fallback to simpler method if PowerShell scheduled task creation fails
        try {
            schtasks /create /tn $startupTaskName /tr "$startupScriptPath" /sc onstart /ru "SYSTEM" /f
            Write-Output "Pre-FSLogix startup task created using schtasks command"
        } catch {
            Write-Output "Fallback task creation also failed: $_"
        }
    }
    
    # 2. Create a post-logon script for the user that runs after FSLogix profile is mounted
    try {
        $postLogonScript = @"
@echo off
echo Starting SolidCAM post-FSLogix setup at %date% %time% > C:\ProgramData\SolidCAM\user_logon.log

REM Wait for FSLogix profile to fully mount
timeout /t 10 /nobreak

REM Check if ShopFloorEditor is already running
tasklist /FI "IMAGENAME eq ShopFloorEditor.exe" | find "ShopFloorEditor.exe" > nul
if errorlevel 1 (
    echo ShopFloorEditor not running, starting it now >> C:\ProgramData\SolidCAM\user_logon.log
    start "" "$editorPath"
) else (
    echo ShopFloorEditor already running >> C:\ProgramData\SolidCAM\user_logon.log
)

REM Add to user's Run key if not already there (this will persist in FSLogix profile)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ShopFloorEditor" > nul 2>&1
if errorlevel 1 (
    echo Adding to user Run key >> C:\ProgramData\SolidCAM\user_logon.log
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ShopFloorEditor" /t REG_SZ /d "$editorPath" /f
)

echo Post-FSLogix user setup completed at %date% %time% >> C:\ProgramData\SolidCAM\user_logon.log
"@
        
        $postLogonScriptPath = "$scriptDir\PostFSLogixSetup.cmd"
        Set-Content -Path $postLogonScriptPath -Value $postLogonScript -Force
        
        # Create a scheduled task to run at user logon
        $postLogonTaskName = "SolidCAM-UserLogonSetup"
        
        # Check if task exists and remove if it does
        $taskExists = Get-ScheduledTask -TaskName $postLogonTaskName -ErrorAction SilentlyContinue
        if ($taskExists) {
            Unregister-ScheduledTask -TaskName $postLogonTaskName -Confirm:$false
        }
        
        # Create new task - this will run for any user that logs in
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$postLogonScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $principal = New-ScheduledTaskPrincipal -GroupId "Users" -LogonType Interactive -RunLevel Highest
        
        Register-ScheduledTask -TaskName $postLogonTaskName `
                               -Action $action `
                               -Trigger $trigger `
                               -Settings $settings `
                               -Principal $principal `
                               -Force
        
        Write-Output "Post-FSLogix user logon task created successfully"
    } catch {
        Write-Output "Error creating post-FSLogix user logon task: $_"
        
        # Fallback to simpler method if PowerShell scheduled task creation fails
        try {
            schtasks /create /tn $postLogonTaskName /tr "$postLogonScriptPath" /sc onlogon /f
            Write-Output "Post-FSLogix user logon task created using schtasks command"
        } catch {
            Write-Output "Fallback task creation also failed: $_"
        }
    }
    
    # 3. Create a delayed verification script that runs after system boot
    try {
        $verificationScript = @"
@echo off
echo Starting delayed verification at %date% %time% > C:\ProgramData\SolidCAM\verification.log

REM Wait to allow FSLogix profiles to mount and user to log in
timeout /t 120 /nobreak

REM Check if ShopFloorEditor is running
tasklist /FI "IMAGENAME eq ShopFloorEditor.exe" | find "ShopFloorEditor.exe" > nul
if errorlevel 1 (
    echo ShopFloorEditor not running after delay, attempting to start >> C:\ProgramData\SolidCAM\verification.log
    
    REM Try to determine if a user is logged in
    query user | find /i "SolidCAMOperator1" > nul
    if not errorlevel 1 (
        echo SolidCAMOperator1 is logged in, starting ShopFloorEditor >> C:\ProgramData\SolidCAM\verification.log
        
        REM Create a temporary task to run in user context
        echo Creating temporary task to launch app >> C:\ProgramData\SolidCAM\verification.log
        schtasks /create /tn "SolidCAM-EmergencyLaunch" /tr "$editorPath" /sc once /st 00:00 /ru SolidCAMOperator1 /f
        schtasks /run /tn "SolidCAM-EmergencyLaunch"
        timeout /t 10 /nobreak
        schtasks /delete /tn "SolidCAM-EmergencyLaunch" /f
    ) else (
        echo No user logged in, cannot start app >> C:\ProgramData\SolidCAM\verification.log
    )
) else (
    echo ShopFloorEditor is already running >> C:\ProgramData\SolidCAM\verification.log
)

echo Verification completed at %date% %time% >> C:\ProgramData\SolidCAM\verification.log
"@
        
        $verificationScriptPath = "$scriptDir\DelayedVerification.cmd"
        Set-Content -Path $verificationScriptPath -Value $verificationScript -Force
        
        # Create a scheduled task to run at system startup with delay
        $verificationTaskName = "SolidCAM-DelayedVerification"
        
        # Check if task exists and remove if it does
        $taskExists = Get-ScheduledTask -TaskName $verificationTaskName -ErrorAction SilentlyContinue
        if ($taskExists) {
            Unregister-ScheduledTask -TaskName $verificationTaskName -Confirm:$false
        }
        
        # Create new task
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$verificationScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName $verificationTaskName `
                               -Action $action `
                               -Trigger $trigger `
                               -Settings $settings `
                               -Principal $principal `
                               -Force
        
        Write-Output "Delayed verification task created successfully"
    } catch {
        Write-Output "Error creating delayed verification task: $_"
    }
    
    Write-Output "Multiple FSLogix-aware startup methods configured. ShopFloorEditor will start automatically after hibernation resume."
}

# 3. Create a post-hibernation validation script
Write-Output "3) Creating post-hibernation validation script..."
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

if (`$shopFloorProcess) {
    Write-Output "SUCCESS: ShopFloorEditor is running with PID: `$(`$shopFloorProcess.Id)"
    
    try {
        Write-Output "Process start time: `$(`$shopFloorProcess.StartTime)"
        
        # Compare process start time with system boot time
        `$processUptime = (Get-Date) - `$shopFloorProcess.StartTime
        
        if (`$processUptime.TotalSeconds -gt `$uptime.TotalSeconds) {
            Write-Output "CONFIRMED: Process start time predates system boot time!"
            Write-Output "This confirms the application state was preserved through hibernation."
        } else {
            Write-Output "NOTE: Process appears to have been started after system boot."
            Write-Output "Application state may not have been preserved through hibernation, but auto-start worked."
        }
    } catch {
        Write-Output "Could not determine process start time: `$_"
    }
} else {
    Write-Output "ShopFloorEditor is not running after hibernation."
    Write-Output "Confirming FSLogix profile status..."
    
    # Check if FSLogix profile is mounted
    `$fslogixRegistry = Test-Path "HKLM:\SOFTWARE\FSLogix\Profiles"
    `$fslogixService = Get-Service "frxsvc" -ErrorAction SilentlyContinue
    
    if (`$fslogixRegistry -and `$fslogixService) {
        Write-Output "FSLogix components detected. Profile mounting may be incomplete."
        Write-Output "Waiting 60 seconds for profile to complete mounting..."
        Start-Sleep -Seconds 60
        
        # Check again after delay
        `$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
        
        if (`$shopFloorProcess) {
            Write-Output "SUCCESS: ShopFloorEditor is now running after delay."
        } else {
            Write-Output "WARNING: ShopFloorEditor still not running after delay."
            Write-Output "Attempting to start it now..."
            
            # Get logged in user to determine if we can start the app
            `$userSession = query user 2>&1
            if (`$userSession -match "SolidCAMOperator1") {
                # Create a temporary task to run as the user
                `$taskName = "SolidCAM-EmergencyStart-`$(Get-Random)"
                schtasks /create /tn `$taskName /tr "$editorPath" /sc once /st 00:00 /ru SolidCAMOperator1 /f
                schtasks /run /tn `$taskName
                
                Write-Output "ShopFloorEditor startup attempted via task scheduler"
                
                # Clean up
                Start-Sleep -Seconds 10
                schtasks /delete /tn `$taskName /f
            } else {
                Write-Output "No user logged in. Cannot start ShopFloorEditor now."
                Write-Output "User will need to log in first."
            }
        }
    } else {
        Write-Output "FSLogix components not fully detected, auto-start may not work correctly."
        Write-Output "Manual intervention may be required."
    }
}

# Log the results
`$logPath = "C:\ProgramData\SolidCAM\hibernation_results.txt"
Add-Content -Path `$logPath -Value "Validation run: `$(Get-Date)"
Add-Content -Path `$logPath -Value "ShopFloorEditor running: `$(`$null -ne `$shopFloorProcess)"
Add-Content -Path `$logPath -Value "FSLogix detected: `$fslogixRegistry"
Add-Content -Path `$logPath -Value "-----------------------------------"
"@

Set-Content -Path $validationScriptPath -Value $validationScript

Write-Output "4) Preparing startup task to validate hibernation on boot..."
$taskName = "SolidCAM-ValidateHibernation"
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $validationScriptPath"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName `
                      -Action $action `
                      -Trigger $trigger `
                      -Settings $settings `
                      -Principal $principal `
                      -Force

Write-Output "Post-hibernation validation task created successfully."

# Log script execution end
$endTime = Get-Date
$executionTime = $endTime - $startTime
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - hibernation_setup.ps1 completed in $($executionTime.TotalSeconds) seconds"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\hibernation_setup_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
ShopFloorEditor running: $($null -ne $shopFloorProcess)
FSLogix-aware configuration completed successfully"