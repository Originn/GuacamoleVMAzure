# hibernation_setup.ps1
# Script to prepare for Azure VM hibernation with application state preservation

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

# Script to prepare for Azure VM hibernation with application state preservation

Write-Output "=== Preparing VM for hibernation with application state preservation ==="

# 1. Verify hibernation is enabled in Windows
Write-Output "1) Checking hibernation status..."
$hibernateStatus = powercfg /a | Select-String "Hibernate"

if ($hibernateStatus -match "Hibernation is not available") {
    Write-Output "Hibernation is not available. Enabling hibernation..."
    powercfg /hibernate on
    powercfg /h /type full
} else {
    Write-Output "Hibernation is available. Ensuring it's set to full..."
    powercfg /h /type full
}

# 2. Verify the page file is on the C: drive (required for hibernation)
Write-Output "2) Checking page file configuration..."
$pageFileSettings = Get-WmiObject -Class Win32_PageFileSetting
$pageFileOnC = $false

foreach ($pagefile in $pageFileSettings) {
    if ($pagefile.Name -like "C:\*") {
        $pageFileOnC = $true
        Write-Output "Page file exists on C: drive"
        break
    }
}

if (-not $pageFileOnC) {
    Write-Output "No page file on C: drive. Configuring page file..."
    # Remove any existing page files
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $computerSystem.AutomaticManagedPagefile = $false
    $computerSystem.Put()
    
    # Remove all existing page files
    Get-WmiObject -Class Win32_PageFileSetting | ForEach-Object {
        $_.Delete()
    }
    
    # Create a page file on C: drive
    $pageFileSetting = New-Object -TypeName System.Management.ManagementClass -ArgumentList "\\.\root\cimv2:Win32_PageFileSetting"
    $pageFileSetting.Create("C:\pagefile.sys", [int]($env:SystemRoot.Substring(0, 1) -eq "C:") * 8192, 16384)
    
    Write-Output "Page file configured on C: drive"
}

# 3. Check if ShopFloorEditor is already running and if not, start it
$editorPath = "C:\Program Files\SolidCAM2024 Maker\solidcam\ShopFloorEditor.exe"
Write-Output "3) Checking if ShopFloorEditor is running..."

$shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

if ($shopFloorProcess) {
    Write-Output "ShopFloorEditor is already running with PID: $($shopFloorProcess.Id)"
} else {
    Write-Output "ShopFloorEditor is not running. Attempting to start it..."
    
    # Try to run as SolidCAMOperator1 if they're logged in
    $operatorSession = query session SolidCAMOperator1 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Output "SolidCAMOperator1 is logged in, launching ShopFloorEditor..."
        try {
            # Get the user's session ID
            $sessionInfo = $operatorSession -split '\s+' | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
            
            if ($sessionInfo) {
                # Use process creation with explicit session ID
                $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processStartInfo.FileName = $editorPath
                $processStartInfo.UseShellExecute = $true
                # Set the session ID for the process
                $processStartInfo.Arguments = "/session:$sessionInfo"
                
                $process = [System.Diagnostics.Process]::Start($processStartInfo)
                Write-Output "ShopFloorEditor launched in session $sessionInfo with PID: $($process.Id)"
            } else {
                Write-Output "Could not determine session ID for SolidCAMOperator1, falling back to simple start"
                Start-Process -FilePath $editorPath
            }
        } catch {
            Write-Output "Error launching ShopFloorEditor: $_"
            Write-Output "Falling back to simpler launch method..."
            Start-Process -FilePath $editorPath
        }
    } else {
        Write-Output "SolidCAMOperator1 not logged in, launching ShopFloorEditor in current context..."
        Start-Process -FilePath $editorPath
    }
    
    # Wait for process to initialize
    Start-Sleep -Seconds 5
    
    # Verify it's running
    $shopFloorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue
    if ($shopFloorProcess) {
        Write-Output "ShopFloorEditor successfully started with PID: $($shopFloorProcess.Id)"
    } else {
        Write-Output "WARNING: ShopFloorEditor did not start successfully"
    }
}

# 4. Create a script to verify the application is still running after resume
Write-Output "4) Creating post-hibernation verification script..."
$postHibernateScript = @"
# post_hibernate_check.ps1
# This script checks if ShopFloorEditor maintained its state through hibernation

Write-Output "=== Post-Hibernation Verification ==="
Write-Output "Checking if ShopFloorEditor is still running..."

`$editorProcess = Get-Process -Name "ShopFloorEditor" -ErrorAction SilentlyContinue

if (`$editorProcess) {
    Write-Output "SUCCESS: ShopFloorEditor is running with PID: `$(`$editorProcess.Id)"
    Write-Output "Memory hibernation and state restoration successful!"
} else {
    Write-Output "WARNING: ShopFloorEditor is not running after hibernation"
    Write-Output "This may indicate that hibernation did not properly restore the application state"
    Write-Output "Consider checking Azure hibernation settings and VM configuration"
}
"@

Set-Content -Path "C:/ProgramData/SolidCAM/post_hibernate_check.ps1" -Value $postHibernateScript -Force

# 5. Create a logon task to run the post-hibernation check
Write-Output "5) Creating verification task for user logon..."

$taskName = "SolidCAM-PostHibernateCheck"
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$argument = "-NoProfile -WindowStyle Normal -ExecutionPolicy Bypass -File C:\ProgramData\SolidCAM\post_hibernate_check.ps1"
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "SolidCAMOperator1"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SolidCAMOperator1" -RunLevel Highest

Register-ScheduledTask -TaskName $taskName `
                     -Action $action `
                     -Trigger $trigger `
                     -Settings $settings `
                     -Principal $principal `
                     -Force

Write-Output "Post-hibernation verification task created successfully"
Write-Output "=== VM hibernation preparation completed ==="

# Log script execution end
$endTime = Get-Date
Add-Content -Path $scriptLogPath -Value "Script execution: $endTime - hibernation_setup.ps1 completed"
Write-Output "=== SCRIPT-ID: hibernation_setup.ps1 completed execution at $endTime ==="

# Create a proof file for this execution
Set-Content -Path "$proofPath\hibernation_setup_ran_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Value "Script executed from $startTime to $endTime
Hibernation setup: Hibernate available: $($hibernateStatus -match 'Hibernation is not available' -eq $false), Page file on C: $pageFileOnC, ShopFloorEditor running: $($null -ne $shopFloorProcess)"