# optimization.ps1

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
Add-Content -Path $scriptLogPath -Value "Script execution: $startTime - optimization.ps1 starting"
Write-Output "=== SCRIPT-ID: optimization.ps1 starting execution at $startTime ==="


Write-Output "=== Starting persistent VM optimizations ==="

# 1. Configure Windows boot settings for faster startup
Write-Output "1) Optimizing boot configuration..."
bcdedit /set bootmenupolicy standard
bcdedit /set {current} bootstatuspolicy ignoreallfailures
bcdedit /timeout 3

# 2. Configure services for faster RDP startup
Write-Output "2) Optimizing service configuration..."
Set-Service -Name TermService     -StartupType Automatic
Set-Service -Name LanmanServer    -StartupType Automatic
Set-Service -Name SessionEnv      -StartupType Automatic
Set-Service -Name UmRdpService    -StartupType Automatic
Start-Service -Name TermService   -ErrorAction SilentlyContinue
Start-Service -Name UmRdpService  -ErrorAction SilentlyContinue

# 3. Registry optimizations for RDP and Explorer performance
Write-Output "3) Applying registry optimizations..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer      /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"      /v VisualFXSetting   /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Desktop"                                              /v UserPreferencesMask /t REG_BINARY /d 9012078010000000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics"                                /v MinAnimate         /t REG_SZ    /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f

# 4. Disable unnecessary startup tasks (OneDrive, Skype, etc.)
Write-Output "4) Disabling unnecessary startup items..."
Get-ScheduledTask |
  Where-Object {
    $_.State -eq "Ready" -and (
      $_.TaskPath -like "*\Startup\*" -or
      $_.TaskName -like "*OneDrive*" -or
      $_.TaskName -like "*Skype*"
    )
  } |
  Disable-ScheduledTask -ErrorAction SilentlyContinue

# 5. SolidCAM-specific configuration (if installed)
$solidcamExe = "C:\Program Files\SolidCAM2024 Maker\solidcam\Solidcam.exe"
if (Test-Path $solidcamExe) {
  Write-Output "5) Optimizing SolidCAM configuration..."
  $configDir = "$solidcamExe\config"
  if (Test-Path $configDir) {
    Copy-Item $configDir "$configDir.cached" -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# 6. Create a startup task for RDP optimizations
Write-Output "6) Creating startup optimization task..."
$psCmd    = '& { Start-Service TermService -Force; Start-Service UmRdpService -Force; ipconfig /flushdns }'
$argument = "-NoProfile -WindowStyle Hidden -Command `"${psCmd}`""
$action   = New-ScheduledTaskAction   -Execute "Powershell.exe" -Argument $argument
$trigger  = New-ScheduledTaskTrigger  -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal= New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SolidCAM-StartupOptimizer" `
                      -Action $action `
                      -Trigger $trigger `
                      -Settings $settings `
                      -Principal $principal `
                      -Force

# 7. Prepare ShopFloorEditor for hibernation
Write-Output "7) Setting up ShopFloorEditor for hibernation..."
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"

# Clean up any existing auto-launch entries
Write-Output "Cleaning up any existing auto-launch entries..."

# Remove any existing scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*ShopFloorEditor*" } | 
    Where-Object { $_.TaskName -ne "SolidCAM-PostHibernateCheck" } | 
    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

# Remove any registry auto-start entries
Write-Output "Removing registry auto-start entries..."
foreach ($i in 1..3) {
    $oldKeyName = "LaunchShopFloorEditor_SolidCAMOperator$i"
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v $oldKeyName /f 2>$null
}
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ShopFloorEditorLauncher" /f 2>$null
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "ShopFloorEditorInit" /f 2>$null

# Remove any startup shortcuts
Write-Output "Removing startup shortcuts..."
$startupFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
Remove-Item "$startupFolder\LaunchShopFloorEditor*.lnk" -Force -ErrorAction SilentlyContinue

# Ensure hibernation is properly configured
Write-Output "Verifying hibernation is properly configured..."

# Check if hibernation is enabled
$hibernateStatus = powercfg /a | Select-String "Hibernate"
if ($hibernateStatus -match "Hibernation is not available") {
    Write-Output "Hibernation not available. Enabling..."
    powercfg /hibernate on
} else {
    Write-Output "Hibernation is available"
}

# Set hibernation type to 'full' (required for application state preservation)
Write-Output "Setting hibernation type to full..."
powercfg /h /type full

# Launch ShopFloorEditor for SolidCAMOperator1 before hibernation
Write-Output "Running ShopFloorEditor for SolidCAMOperator1 before hibernation..."

# Check if ShopFloorEditor is already running
$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
if ($shopFloorProcess) {
    Write-Output "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
} else {
    # Try to detect if SolidCAMOperator1 is logged in
    # Try to detect if SolidCAMOperator1 is logged in
    query session SolidCAMOperator1 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Output "SolidCAMOperator1 is logged in, launching ShopFloorEditor..."
        try {
            # Launch directly since operator is logged in
            Start-Process -FilePath $editorPath
            Start-Sleep -Seconds 3  # Give it time to start
            
            # Verify it's running
            $newProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
            if ($newProcess) {
                Write-Output "ShopFloorEditor successfully started with PID: $($newProcess.Id)"
            } else {
                Write-Output "WARNING: Failed to start ShopFloorEditor"
            }
        } catch {
            Write-Output "Error launching ShopFloorEditor: $_"
        }
    } else {
        Write-Output "SolidCAMOperator1 not logged in, cannot launch ShopFloorEditor in user context"
        Write-Output "Will create startup task instead"
        
        # Create a task to launch ShopFloorEditor at user logon
        $taskName = "SolidCAM-LaunchShopFloorEditor"
        $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($taskExists) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        
        $action = New-ScheduledTaskAction -Execute $editorPath
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "SolidCAMOperator1"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SolidCAMOperator1" -LogonType Interactive -RunLevel Highest
        
        Register-ScheduledTask -TaskName $taskName `
                             -Action $action `
                             -Trigger $trigger `
                             -Settings $settings `
                             -Principal $principal `
                             -Force
                             
        Write-Output "Created logon task to launch ShopFloorEditor for SolidCAMOperator1"
    }
}

# Run the dedicated hibernation setup script if it exists
$hibernationSetupScript = "C:\users\ori.somekh\desktop\solidcamfunctionapp\hibernation_setup.ps1"
if (Test-Path $hibernationSetupScript) {
    Write-Output "Running dedicated hibernation setup script..."
    & $hibernationSetupScript
} else {
    Write-Output "Hibernation setup script not found. This is okay if you're not using advanced hibernation features."
}


Write-Output "=== Persistent VM optimization completed ==="

# Log script execution end
$endTime = Get-Date
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - optimization.ps1 completed"
Write-Output "=== SCRIPT-ID: optimization.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\optimization_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
Optimization results: Boot optimized, Services configured, ShopFloorEditor running: $($null -ne $shopFloorProcess)"
