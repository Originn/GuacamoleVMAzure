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
Write-Output "Granting local Administrators group membership to all SolidCAMOperator accounts"
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator1" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator2" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "SolidCAMOperator3" -ErrorAction SilentlyContinue

# Create one-time logon script: launch ShopFloorEditor and capture desktop screenshot
$captureScriptPath = "C:\ProgramData\SolidCAM\OneTimeCaptureAndStart.ps1"
$captureScript = @"
Start-Process 'C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe'
Start-Sleep -Seconds 10
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
`$width = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
`$height = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
`$bmp = New-Object System.Drawing.Bitmap(`$width, `$height)
`$graphics = [System.Drawing.Graphics]::FromImage(`$bmp)
`$graphics.CopyFromScreen([System.Windows.Forms.SystemInformation]::VirtualScreen.X, [System.Windows.Forms.SystemInformation]::VirtualScreen.Y, 0, 0, `$bmp.Size)
if (-not (Test-Path 'C:\ProgramData\SolidCAM')) { New-Item -Path 'C:\ProgramData\SolidCAM' -ItemType Directory -Force }
`$bmp.Save('C:\ProgramData\SolidCAM\screenshot.png', [System.Drawing.Imaging.ImageFormat]::Png)
schtasks /Delete /TN 'OneTimeShopFloorStarter' /F -ErrorAction SilentlyContinue
Remove-Item -Path `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"@
if (!(Test-Path -Path (Split-Path -Parent $captureScriptPath) -PathType Container)) {
    New-Item -Path (Split-Path -Parent $captureScriptPath) -ItemType Directory -Force
}
$captureScript | Out-File -FilePath $captureScriptPath -Encoding UTF8
$xmlTaskContent = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts ShopFloorEditor at logon</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>SolidCAMOperator1</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>SolidCAMOperator1</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$captureScriptPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Save the XML file
$xmlTaskPath = "C:\ProgramData\SolidCAM\ShopFloorStartup.xml"
$xmlTaskContent | Out-File -FilePath $xmlTaskPath -Encoding Unicode

# Create task using the XML
schtasks /Delete /TN 'OneTimeShopFloorStarter' /F 2>$null
schtasks /Create /TN 'OneTimeShopFloorStarter' /XML "$xmlTaskPath" /F
Write-Output "Creating permanent scheduled task for ShopFloorEditor on every user logon"
# Define permanent scheduled task using PowerShell cmdlets to avoid quoting issues
$actionPerm = New-ScheduledTaskAction -Execute "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
$triggerPerm = New-ScheduledTaskTrigger -AtLogOn
$principalPerm = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "ShopFloorEditorAtLogon" -Action $actionPerm -Trigger $triggerPerm -Principal $principalPerm -Force