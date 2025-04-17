# run_shopfloor.ps1
# Simple script to launch ShopFloorEditor under SolidCAMOperator1 before hibernation
# Also ensures the screen is unlocked and visible after hibernation

Write-Output "=== Starting ShopFloorEditor for SolidCAMOperator1 ==="

# Path to the ShopFloorEditor executable
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"

# Check if the executable exists
if (!(Test-Path $editorPath)) {
    Write-Output "ERROR: ShopFloorEditor not found at: $editorPath"
    exit 1
}

# Create scripts directory for post-resume scripts
$scriptsDir = "C:\ProgramData\SolidCAM"
if (!(Test-Path $scriptsDir)) {
    New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
}

# Create a script that will run after resume to ensure the screen is visible
$postResumeScriptPath = "$scriptsDir\post_resume.ps1"
$postResumeScript = @"
# Script to run after VM resume to ensure screen is visible
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DisplayState {
    [DllImport("user32.dll")]
    public static extern int ShowWindow(int hwnd, int command);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
}
"@

# Keep session awake
\$sleepPrevention = New-Object -TypeName System.Diagnostics.Process
\$sleepPrevention.StartInfo.FileName = "powercfg.exe"
\$sleepPrevention.StartInfo.Arguments = "/requestsoverride PROCESS DISPLAY \$pid"
\$sleepPrevention.StartInfo.UseShellExecute = \$false
\$sleepPrevention.Start()

# Ensure screen is unlocked
\$wsh = New-Object -ComObject WScript.Shell
\$wsh.SendKeys("%{TAB}")
Start-Sleep -Seconds 1
\$wsh.SendKeys(" ")

# Log to a file the resume happened
Add-Content -Path "C:\ProgramData\SolidCAM\resume_log.txt" -Value "VM resumed at \$(Get-Date)"
"@

Set-Content -Path $postResumeScriptPath -Value $postResumeScript

# Create a startup task to run the post-resume script
$taskName = "SolidCAM-PostResume"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$postResumeScriptPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SolidCAMOperator1" -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
Write-Output "Post-resume task created to ensure screen is visible after hibernation"

# Set up auto-logon for SolidCAMOperator1
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1" -Type String
Set-ItemProperty -Path $RegPath -Name "DefaultUserName" -Value "SolidCAMOperator1" -Type String
Set-ItemProperty -Path $RegPath -Name "DefaultPassword" -Value "Rt@wqPP7ZvUgtS7" -Type String
Set-ItemProperty -Path $RegPath -Name "DefaultDomainName" -Value "." -Type String

# Disable lock screen and screen saver
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}
Set-ItemProperty -Path $RegPath -Name "NoLockScreen" -Value 1 -Type DWord
$RegPath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $RegPath -Name "ScreenSaveActive" -Value "0" -Type String

# Configure power settings to prevent display from turning off
& powercfg /change monitor-timeout-ac 0
& powercfg /change standby-timeout-ac 0

# Disable hibernate button and sleep button
& powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 0
& powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 94ac6d29-73ce-41a6-809f-6363ba21b47e 0

# Create a base initialization script
$baseInitScript = @"
# Base initialization script
Add-Content -Path "C:\ProgramData\SolidCAM\initialization_log.txt" -Value "Initialization ran at \$(Get-Date)"

# Keep the display on and session active
\$wsh = New-Object -ComObject WScript.Shell
while (\$true) {
    # Send a harmless key combination every minute to prevent screen lock
    \$wsh.SendKeys("+{F15}")
    Start-Sleep -Seconds 60
}
"@
Set-Content -Path "$scriptsDir\keep_active.ps1" -Value $baseInitScript

# Create a task to run the initialization script
$taskName = "SolidCAM-KeepActive"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptsDir\keep_active.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogon -User "SolidCAMOperator1"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
$principal = New-ScheduledTaskPrincipal -UserId "SolidCAMOperator1" -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
Write-Output "Keep-active task created to prevent screen from locking"

# Check if the SolidCAMOperator1 user exists, create if it doesn't
$userExists = Get-LocalUser -Name "SolidCAMOperator1" -ErrorAction SilentlyContinue
if (!$userExists) {
    Write-Output "Creating SolidCAMOperator1 user account..."
    $securePassword = ConvertTo-SecureString "Rt@wqPP7ZvUgtS7" -AsPlainText -Force
    New-LocalUser -Name "SolidCAMOperator1" -Password $securePassword -FullName "SolidCAM Operator 1" -Description "SolidCAM User Account" -AccountNeverExpires
    Add-LocalGroupMember -Group "Users" -Member "SolidCAMOperator1"
}

# Check if SolidCAMOperator1 is logged in
$operatorLoggedIn = query session SolidCAMOperator1 2>$null
$isLoggedIn = ($LASTEXITCODE -eq 0)

if ($isLoggedIn) {
    Write-Output "SolidCAMOperator1 is logged in. Starting ShopFloorEditor..."
    
    # Create a simple launcher script that will run in the user's context
    $launcherPath = "$scriptsDir\launch_editor.ps1"
    
    Set-Content -Path $launcherPath -Value "Start-Process -FilePath '$editorPath'"
    
    # Create and run a scheduled task to launch the application in the user's context
    $taskName = "LaunchShopFloorEditor"
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $launcherPath"
    $principal = New-ScheduledTaskPrincipal -UserId "SolidCAMOperator1" -LogonType Interactive -RunLevel Highest
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force
    Start-ScheduledTask -TaskName $taskName
    
    Write-Output "Waiting for ShopFloorEditor to start..."
    
    # Wait up to 30 seconds for the process to appear
    $timeout = 30
    $interval = 2
    $elapsed = 0
    
    while ($elapsed -lt $timeout) {
        Start-Sleep -Seconds $interval
        $elapsed += $interval
        
        $shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
        if ($shopFloorProcess) {
            Write-Output "ShopFloorEditor started successfully with PID: $($shopFloorProcess.Id)"
            
            # Wait an additional 10 seconds for the application to initialize
            Write-Output "Waiting 10 more seconds for initialization..."
            Start-Sleep -Seconds 10
            
            # Clean up the task
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            
            Write-Output "ShopFloorEditor is running and ready for hibernation"
            exit 0
        }
        
        Write-Output "Still waiting... ($elapsed seconds elapsed)"
    }
    
    Write-Output "Failed to detect ShopFloorEditor process after $timeout seconds"
    exit 1
    
} else {
    Write-Output "SolidCAMOperator1 is not logged in."
    
    # Create auto-start for ShopFloorEditor
    Write-Output "Setting up auto-start for ShopFloorEditor on login..."
    $startupFolder = "C:\Users\SolidCAMOperator1\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    
    if (!(Test-Path $startupFolder)) {
        New-Item -Path $startupFolder -ItemType Directory -Force | Out-Null
    }
    
    # Create a shortcut
    $shortcutPath = "$startupFolder\ShopFloorEditor.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $editorPath
    $Shortcut.Save()
    
    Write-Output "Auto-login and auto-start configured. ShopFloorEditor will start after next boot when SolidCAMOperator1 logs in."
    
    # We can't launch ShopFloorEditor now since SolidCAMOperator1 isn't logged in
    exit 0
}
