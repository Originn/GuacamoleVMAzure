# optimization.ps1

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

# 7. Remove old ShopFloorEditor auto-launch entries and run it once before hibernation
Write-Output "7) Setting up ShopFloorEditor for hibernation test..."
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"

# Clean up any existing auto-launch entries
Write-Output "Cleaning up any existing auto-launch entries..."

# Remove any existing scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*ShopFloorEditor*" } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

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

# Launch ShopFloorEditor for SolidCAMOperator1 only before hibernation
Write-Output "Running ShopFloorEditor for SolidCAMOperator1 before hibernation..."

# Use PSExec-like functionality to launch the app in the SolidCAMOperator1 session
$runAsUserScript = @"
@echo off
C:\Windows\System32\query.exe session SolidCAMOperator1 > %TEMP%\session.txt
for /f "tokens=2" %%i in ('type %TEMP%\session.txt ^| find "SolidCAMOperator1"') do set SESSION=%%i
if defined SESSION (
    C:\Windows\System32\wmic.exe path win32_process call create "$editorPath" /user:SolidCAMOperator1 
    echo Started ShopFloorEditor for SolidCAMOperator1
) else (
    echo SolidCAMOperator1 not logged in
)
del %TEMP%\session.txt
"@

$scriptPath = "C:\ProgramData\SolidCAM\RunAsSolidCAMOperator1.bat"
if (!(Test-Path "C:\ProgramData\SolidCAM")) {
    New-Item -Path "C:\ProgramData\SolidCAM" -ItemType Directory -Force | Out-Null
}
Set-Content -Path $scriptPath -Value $runAsUserScript -Force

# Try to run the script
try {
    Start-Process -FilePath $scriptPath -Wait -NoNewWindow
    Write-Output "ShopFloorEditor launch attempt completed."
    
    # Alternative method - check if user is logged in and launch directly
    query session SolidCAMOperator1 >$null 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Output "SolidCAMOperator1 is logged in, launching ShopFloorEditor directly..."
        Start-Process -FilePath $editorPath
        Write-Output "ShopFloorEditor launched directly."
    } else {
        Write-Output "SolidCAMOperator1 not logged in, can't launch ShopFloorEditor at this time."
    }
} catch {
    Write-Output "Error launching ShopFloorEditor: $_"
}

Write-Output "=== Persistent VM optimization completed ==="
