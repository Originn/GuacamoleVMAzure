<#
 OneTimeHibernationSetup.ps1
 One-time guest script: enables hibernate, configures auto-logon, creates a one-off task to start ShopFloorEditor, then exits.
#>

# Enable full hibernation
powercfg /hibernate on
powercfg /h /type full

# Configure auto-logon for SolidCAMOperator1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d SolidCAMOperator1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rt@wqPP7ZvUgtS7 /f

# Create one-time scheduled task to start ShopFloorEditor at logon
$taskName = "OneTimeShopFloorStarter"
schtasks /Delete /TN $taskName /F 2>$null
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"Start-Process -FilePath 'C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe'; Start-Sleep -Seconds 10; schtasks /Delete /TN $taskName /F\""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "SolidCAMOperator1"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force