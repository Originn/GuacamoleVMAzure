# run_shopfloor.ps1
# Script to launch ShopFloorEditor for SolidCAMOperator1
# Modified to work with FSLogix profile management

Write-Output "=== Starting ShopFloorEditor for SolidCAMOperator1 ==="

# Path to the ShopFloorEditor executable
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"

# Check if the executable exists
if (!(Test-Path $editorPath)) {
    Write-Output "ERROR: ShopFloorEditor not found at: $editorPath"
    exit 1
}

# Check if ShopFloorEditor is already running
$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

if ($shopFloorProcess) {
    Write-Output "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
    exit 0
}

# Create machine-level preparations for auto-startup (FSLogix profile aware)
try {
    Write-Output "Setting up auto-start mechanisms (compatible with FSLogix profiles)..."
    
    # Create required directories
    $startupScriptsDir = "C:\ProgramData\SolidCAM\StartupScripts"
    if (!(Test-Path $startupScriptsDir)) {
        New-Item -Path $startupScriptsDir -ItemType Directory -Force | Out-Null
    }
    
    # Create a Group Policy startup script that will run before FSLogix mounts profiles
    $gpStartupScript = @"
@echo off
echo Running SolidCAM startup script at %date% %time% > C:\ProgramData\SolidCAM\startup_log.txt

REM Set up auto-logon for SolidCAMOperator1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d SolidCAMOperator1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rt@wqPP7ZvUgtS7 /f

REM Create default startup programs for all users
if not exist "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" mkdir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
echo Set oWS = WScript.CreateObject("WScript.Shell") > "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
echo sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ShopFloorEditor.lnk" >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
echo oLink.TargetPath = "$editorPath" >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
echo oLink.Save >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
cscript //nologo "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"
del "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\StartShopFloorEditor.vbs"

echo Setup completed at %date% %time% >> C:\ProgramData\SolidCAM\startup_log.txt
"@
    
    $gpStartupScriptPath = "$startupScriptsDir\StartupPrep.cmd"
    Set-Content -Path $gpStartupScriptPath -Value $gpStartupScript -Force
    
    # Create task to run our script at system startup (before user login and FSLogix)
    $taskName = "SolidCAM-SystemStartup"
    
    # Remove existing task if present
    schtasks /query /tn $taskName 2>$null
    if ($LASTEXITCODE -eq 0) {
        schtasks /delete /tn $taskName /f
    }
    
    # Create task running as SYSTEM at startup
    schtasks /create /tn $taskName /tr "$gpStartupScriptPath" /sc onstart /ru "SYSTEM" /f
    
    Write-Output "System startup task created successfully"
    
    # Create a startup verification script that runs with a delay
    $verificationScript = @"
@echo off
echo Running delayed verification at %date% %time% > C:\ProgramData\SolidCAM\verification_log.txt

REM Wait for login to complete and FSLogix to mount profiles
timeout /t 120 /nobreak

REM Check if ShopFloorEditor is running
tasklist /FI "IMAGENAME eq ShopFloorEditor.exe" | find "ShopFloorEditor.exe" > nul
if errorlevel 1 (
    echo ShopFloorEditor not running, attempting to start it >> C:\ProgramData\SolidCAM\verification_log.txt
    start "" "$editorPath"
) else (
    echo ShopFloorEditor already running >> C:\ProgramData\SolidCAM\verification_log.txt
)
"@
    
    $verificationScriptPath = "$startupScriptsDir\VerifyShopFloor.cmd"
    Set-Content -Path $verificationScriptPath -Value $verificationScript -Force
    
    # Create task to run verification with a delay after startup
    $verifyTaskName = "SolidCAM-DelayedVerification"
    
    # Remove existing task if present
    schtasks /query /tn $verifyTaskName 2>$null
    if ($LASTEXITCODE -eq 0) {
        schtasks /delete /tn $verifyTaskName /f
    }
    
    # Create task running as SYSTEM at startup with higher priority
    schtasks /create /tn $verifyTaskName /tr "$verificationScriptPath" /sc onstart /ru "SYSTEM" /f
    
    Write-Output "Verification task created successfully"
} catch {
    Write-Output "Error setting up auto-start mechanisms: $_"
}

# Check if SolidCAMOperator1 is logged in
$operatorLoggedIn = query session SolidCAMOperator1 2>$null
$isLoggedIn = ($LASTEXITCODE -eq 0)

if (!$isLoggedIn) {
    Write-Output "SolidCAMOperator1 is not logged in. Configuring for auto-login at next boot."
    
    try {
        # We know this may not work now, but we can set up the system for next boot
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        # Set auto-logon values
        Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1" -Type String
        Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value "SolidCAMOperator1" -Type String
        Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value "Rt@wqPP7ZvUgtS7" -Type String
        
        Write-Output "Auto-login configured for next boot"
        
        # Create evidence that we've set this up
        Set-Content -Path "C:\ProgramData\SolidCAM\auto_login_configured.txt" -Value "Configured at $(Get-Date)" -Force
        
        # Create a global startup shortcut that will work even with FSLogix
        $allUsersStartupFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        if (!(Test-Path $allUsersStartupFolder)) {
            New-Item -Path $allUsersStartupFolder -ItemType Directory -Force | Out-Null
        }
        
        # Use a VBScript to create the shortcut (more compatible)
        $shortcutScript = @"
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "$allUsersStartupFolder\ShopFloorEditor.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "$editorPath"
oLink.Save
"@
        
        $scriptPath = "C:\ProgramData\SolidCAM\create_shortcut.vbs"
        Set-Content -Path $scriptPath -Value $shortcutScript -Force
        
        # Run the script to create the shortcut
        Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo `"$scriptPath`"" -NoNewWindow -Wait
        
        Write-Output "Global startup shortcut created successfully"
        
        # Since the user isn't logged in, we'll exit here. Next boot will auto-start the app.
        Write-Output "ShopFloorEditor will start automatically after next VM restart and user login."
        exit 0
    } catch {
        Write-Output "Error during auto-login configuration: $_"
        exit 1
    }
} else {
    Write-Output "SolidCAMOperator1 is logged in. Attempting to start ShopFloorEditor directly..."
    
    # Try to get the user's session ID
    try {
        $sessions = query session | Out-String
        $sessionLines = $sessions -split "`n" | Where-Object { $_ -match "SolidCAMOperator1" }
        
        if ($sessionLines) {
            $sessionLine = $sessionLines[0]
            $sessionId = [regex]::Match($sessionLine, '\s+(\d+)\s+').Groups[1].Value
            
            if ($sessionId) {
                Write-Output "Found session ID: $sessionId"
                
                # Method 1: Try using RunAsUser to start the process in the user's session
                $runAsMethod1Success = $false
                
                try {
                    # Create a cmd script to execute
                    $cmdScript = @"
@echo off
start "" "$editorPath"
"@
                    $cmdScriptPath = "C:\ProgramData\SolidCAM\launch_shopfloor.cmd"
                    Set-Content -Path $cmdScriptPath -Value $cmdScript -Force
                    
                    # Use PsExec if available or another method to run in user's session
                    $psExecPath = "C:\Windows\System32\PsExec.exe"
                    if (Test-Path $psExecPath) {
                        Start-Process -FilePath $psExecPath -ArgumentList "-accepteula -i $sessionId -s cmd /c `"$cmdScriptPath`"" -NoNewWindow
                        Start-Sleep -Seconds 5
                        $runAsMethod1Success = $true
                        Write-Output "Attempted to start ShopFloorEditor using PsExec"
                    }
                } catch {
                    Write-Output "Error with Method 1: $_"
                }
                
                # Method 2: Use scheduled task to run immediately
                if (!$runAsMethod1Success) {
                    try {
                        # Create unique task name
                        $taskName = "SolidCAM-LaunchNow-$([Guid]::NewGuid().ToString('N'))"
                        
                        # Create the task directly with schtasks command
                        schtasks /create /tn $taskName /tr "`"$editorPath`"" /sc once /st 00:00 /ru SolidCAMOperator1 /f
                        
                        if ($LASTEXITCODE -eq 0) {
                            # Run the task immediately
                            schtasks /run /tn $taskName
                            Start-Sleep -Seconds 5
                            
                            # Try to clean up
                            schtasks /delete /tn $taskName /f 2>$null
                            
                            Write-Output "Attempted to start ShopFloorEditor using scheduled task"
                        } else {
                            Write-Output "Failed to create task: ExitCode=$LASTEXITCODE"
                        }
                    } catch {
                        Write-Output "Error with Method 2: $_"
                    }
                }
            }
        }
    } catch {
        Write-Output "Error determining session: $_"
    }
    
    # Method 3: Direct method as fallback (may not work with FSLogix but worth trying)
    try {
        Write-Output "Trying direct launch method..."
        Start-Process -FilePath $editorPath -NoNewWindow
    } catch {
        Write-Output "Error with direct method: $_"
    }
    
    # Wait for it to initialize
    Start-Sleep -Seconds 10
    
    # Final verification
    $shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
    if ($shopFloorProcess) {
        Write-Output "SUCCESS: ShopFloorEditor is now running with PID: $($shopFloorProcess.Id)"
    } else {
        Write-Output "WARNING: ShopFloorEditor was not found running after all attempts"
        Write-Output "ShopFloorEditor launch will be attempted automatically at next VM startup"
    }
}

Write-Output "=== ShopFloorEditor launch process complete ==="