// Program.cs - Optimized for faster VM pool initialization and deployment

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection; 
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using Azure;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.ResourceManager.Resources;
using Azure.Core;
using DeployVMFunction;
using Microsoft.Extensions.Configuration;

// Create task that initializes the VM pool in the background
var initializePoolTask = Task.Run(async () =>
{
    // Set up basic console logging for the initialization process
    using var loggerFactory = LoggerFactory.Create(builder =>
    {
        // Add console logger with more detailed information
        builder.AddConsole(options => options.IncludeScopes = true);
        builder.SetMinimumLevel(LogLevel.Information);
    });

    // Set up configuration to read settings
    var configuration = new ConfigurationBuilder()
        .SetBasePath(Environment.CurrentDirectory)
        .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
        .AddEnvironmentVariables()
        .Build();

    // Create a logger instance
    var logger = loggerFactory.CreateLogger("VMPoolInitialization");

    // --- Configuration Reading ---
    // Check if the pool initialization feature is enabled in settings. Default to false.
    bool initializeVMPool = configuration.GetValue("VMPoolSettings__InitializePool", false);

    if (!initializeVMPool)
    {
        logger.LogInformation("VM pool initialization is disabled via configuration (VMPoolSettings:InitializePool = false). Skipping initialization.");
        return; // Stop execution of this task if disabled
    }

    // Read the desired minimum pool size. Default to 2 if not specified.
    int minPoolSize = configuration.GetValue("MIN_POOL_SIZE", 2);
    
    // NEW: Read the warm-up time. Default to 3 minutes (180 seconds) for proper initialization
    int warmupDelaySeconds = configuration.GetValue("VMPoolSettings__WarmupDelaySeconds", 180);
    
    // NEW: Read the maximum number of attempts for service checks
    int maxServiceCheckAttempts = configuration.GetValue("VMPoolSettings__MaxServiceCheckAttempts", 10);
    
    // NEW: Read the delay between service check attempts
    int serviceCheckDelaySeconds = configuration.GetValue("VMPoolSettings__ServiceCheckDelaySeconds", 10);

    logger.LogInformation($"Target minimum VM pool size configured: {minPoolSize}");
    logger.LogInformation($"VM warm-up time configured: {warmupDelaySeconds} seconds");

    // --- VM Pool Management ---
    try
    {
        var poolManager = new VMPoolManager(logger);
        
        logger.LogInformation("Attempting to clean up any orphaned Azure resources (VMs, NICs, Disks) tagged for the pool...");
        await poolManager.CleanupOrphanedResourcesAsync();
        logger.LogInformation("Orphaned resource cleanup process completed.");

        logger.LogInformation("Checking current VM pool status...");
        var status = await poolManager.GetPoolStatusAsync();
        logger.LogInformation($"Initial pool status: {status.DeallocatedVMs.Count} deallocated VM(s) found in the pool.");

        // Determine how many VMs need to be created
        int needed = minPoolSize - status.DeallocatedVMs.Count;

        if (needed > 0)
        {
            logger.LogInformation($"Pool needs {needed} new VM(s) to reach the target size of {minPoolSize}. Starting creation and warm-up process.");

            var newVMs = new List<VirtualMachineResource>(); // To hold references to successfully created VMs

            // Step 1: Create VMs (in parallel)
            logger.LogInformation($"--- Phase 1: Creating {needed} VM(s) ---");
            List<Task<VirtualMachineResource>> creationTasks = new List<Task<VirtualMachineResource>>();
            for (int i = 0; i < needed; i++)
            {
                logger.LogInformation($"=========== STARTING VM CREATION PROCESS ===========");
                logger.LogInformation($"Current time: {DateTime.Now}");
                try
                {
                    // Test the Azure connection before trying to create VMs
                    logger.LogInformation("Testing Azure credentials and access...");
                    var credential = new DefaultAzureCredential();
                    var armClient = new ArmClient(credential);
                    var subscription = await armClient.GetDefaultSubscriptionAsync();
                    logger.LogInformation($"Successfully connected to subscription: {subscription.Data.SubscriptionId}");
                    
                    // Check if we can see the resource group
                    var resourceGroup = await subscription.GetResourceGroupAsync(
                        Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP") ?? "SolidCAM-Golden-Image_group");
                    logger.LogInformation($"Successfully found resource group: {resourceGroup.Value.Data.Name}"); // Added .Value
                    
                    // Test if we can access the VMPool manager's functionality
                    var testStatus = await poolManager.GetPoolStatusAsync();
                    logger.LogInformation($"Initial VM Pool status - Running: {testStatus.RunningVMs.Count}, " +
                                         $"Deallocated: {testStatus.DeallocatedVMs.Count}, " +
                                         $"Transitioning: {testStatus.TransitioningVMs.Count}, " +
                                         $"Other: {testStatus.OtherVMs.Count}");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "ERROR during Azure connection test. VM creation may fail!");
                }


                // Add this before the VM warmup code (around line 120):

                logger.LogInformation($"=========== VM CREATION COMPLETED, STARTING WARMUP ===========");
                logger.LogInformation($"Created VMs: {string.Join(", ", newVMs.Select(vm => vm.Data.Name))}");
                creationTasks.Add(poolManager.CreateAndReturnRunningVMAsync("pool"));
            }
            
            // Wait for all creation tasks and handle results/exceptions with improved error handling
            var creationResults = await Task.WhenAll(creationTasks.Select(async task => {
                try {
                    var vm = await task;
                    logger.LogInformation($"Successfully created VM: {vm.Data.Name} (State: Deallocated)");
                    return vm;
                } catch (Exception ex) {
                    logger.LogError(ex, "Failed to create a VM during pool initialization.");
                    return null; // Indicate failure
                }
            }));
            
            newVMs.AddRange(creationResults.Where(vm => vm != null)); // Add only successfully created VMs
            logger.LogInformation($"--- Phase 1 Complete: {newVMs.Count} out of {needed} VMs created successfully ---");

            // Step 2: Warm-up VMs with enhanced initialization and verification
            if (newVMs.Any())
            {
                 logger.LogInformation($"--- Phase 2: Warming up {newVMs.Count} new VM(s) with enhanced validation ---");
                 
                 // Process each VM in parallel for efficient processing
                 List<Task> warmupTasks = new List<Task>();
                 foreach (var vm in newVMs)
                 {
                     warmupTasks.Add(ProcessVMWarmupAsync(vm, warmupDelaySeconds, maxServiceCheckAttempts, serviceCheckDelaySeconds, logger));
                 }
                 
                 // Wait for all VMs to complete their warm-up process
                 await Task.WhenAll(warmupTasks);
                 logger.LogInformation($"--- Phase 2 Complete: Warm-up process finished for {newVMs.Count} VMs ---");
            } 
            else 
            {
                 logger.LogInformation("--- Phase 2 Skipped: No new VMs were successfully created to warm up. ---");
            }

            // Final status check after initialization
            var finalStatus = await poolManager.GetPoolStatusAsync();
            logger.LogInformation($"Pool initialization complete. Final pool status: {finalStatus.DeallocatedVMs.Count} deallocated VM(s) available.");
        }
        else
        {
            logger.LogInformation($"Pool size ({status.DeallocatedVMs.Count}) already meets or exceeds minimum ({minPoolSize}). No action needed.");
        }
    }
    catch (Exception ex)
    {
        logger.LogCritical(ex, "A critical error occurred during the VM pool management process. Pool might be in an inconsistent state.");
        // Don't throw here as we don't want to prevent the host from starting
    }
});

Console.WriteLine("======= VM POOL INITIALIZATION STARTED =======");
Console.WriteLine($"Current time: {DateTime.Now}");
Console.WriteLine($"Current directory: {Environment.CurrentDirectory}");

try
{
    // Read config values BEFORE creating the logger to ensure we can see any issues
    Console.WriteLine("Reading configuration...");
    var tempConfig = new ConfigurationBuilder()
        .SetBasePath(Environment.CurrentDirectory)
        .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
        .AddEnvironmentVariables()
        .Build();
    
    bool isPoolEnabled = tempConfig.GetValue("VMPoolSettings__InitializePool", false);
    int configuredPoolSize = tempConfig.GetValue("MIN_POOL_SIZE", 0);
    
    Console.WriteLine($"DEBUG: VMPoolSettings__InitializePool = {isPoolEnabled}");
    Console.WriteLine($"DEBUG: MIN_POOL_SIZE = {configuredPoolSize}");
    
    // If using dotnet environment variables format, also check those
    bool isPoolEnabledAlt = tempConfig.GetValue("VMPoolSettings:InitializePool", false);
    Console.WriteLine($"DEBUG: VMPoolSettings:InitializePool (alt format) = {isPoolEnabledAlt}");
    
    // Dump all environment variables for debugging (just the ones with VM in the name)
    foreach (var env in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>())
    {
        if (env.Key.ToString().ToUpper().Contains("VM") || 
            env.Key.ToString().ToUpper().Contains("POOL") ||
            env.Key.ToString().ToUpper().Contains("AZURE"))
        {
            Console.WriteLine($"ENV VAR: {env.Key} = {env.Value}");
        }
    }
}
catch (Exception configEx)
{
    Console.WriteLine($"ERROR during config initialization: {configEx.Message}");
    Console.WriteLine($"Stack trace: {configEx.StackTrace}");
}

// NEW: Extract the VM warm-up process to a separate method for better readability and maintenance
static async Task ProcessVMWarmupAsync(VirtualMachineResource vm, int warmupDelaySeconds, int maxAttempts, int attemptDelaySeconds, ILogger logger)
{
    try
    {
        // Start the VM
        logger.LogInformation($"Starting VM {vm.Data.Name} for warm-up...");
        await vm.PowerOnAsync(Azure.WaitUntil.Completed);
        logger.LogInformation($"VM {vm.Data.Name} started.");
        
        // Get the VM's private IP address for testing connectivity
        string? vmPrivateIp = await GetVMPrivateIpAsync(vm, logger);
        if (string.IsNullOrEmpty(vmPrivateIp))
        {
            logger.LogWarning($"Could not determine private IP for VM {vm.Data.Name}. Will continue with warm-up but connectivity testing will be skipped.");
        }
        
        // First, allow some base initialization time
        logger.LogInformation($"Allowing initial boot time of 60 seconds for VM {vm.Data.Name}...");
        await Task.Delay(TimeSpan.FromSeconds(60));
        
        // Test for RDP connectivity if we have an IP
        bool rdpReady = false;
        if (!string.IsNullOrEmpty(vmPrivateIp))
        {
            rdpReady = await WaitForRdpServiceAsync(vmPrivateIp, maxAttempts, attemptDelaySeconds, logger);
            if (rdpReady)
            {
                logger.LogInformation($"RDP service on VM {vm.Data.Name} is responding.");
            }
            else
            {
                logger.LogWarning($"RDP service on VM {vm.Data.Name} did not become responsive after {maxAttempts} attempts.");
            }
        }
        
        // Run initialization script to ensure all services are started and initialized
        logger.LogInformation($"Running initialization script on VM {vm.Data.Name}...");
        await RunInitializationScriptAsync(vm, logger);
        
        // Wait for any remaining warm-up time
        int remainingWarmupTime = Math.Max(0, warmupDelaySeconds - 60 - (maxAttempts * attemptDelaySeconds));
        if (remainingWarmupTime > 0)
        {
            logger.LogInformation($"Waiting additional {remainingWarmupTime}s for full initialization of VM {vm.Data.Name}...");
            await Task.Delay(TimeSpan.FromSeconds(remainingWarmupTime));
        }
        
        // Run final verification before deallocating
        await RunFinalVerificationAsync(vm, logger);
        
        // Deallocate the VM
        logger.LogInformation($"Warm-up complete for {vm.Data.Name}. Deallocating...");
        await vm.DeallocateAsync(Azure.WaitUntil.Completed);
        logger.LogInformation($"VM {vm.Data.Name} deallocated and returned to pool.");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, $"Error during warm-up or deallocation for VM {vm.Data.Name}. It may require manual attention.");
        
        // Try to deallocate the VM if an exception occurred, to avoid leaving it running
        try
        {
            logger.LogInformation($"Attempting to deallocate VM {vm.Data.Name} after error...");
            await vm.DeallocateAsync(Azure.WaitUntil.Completed);
            logger.LogInformation($"Successfully deallocated VM {vm.Data.Name} after error.");
        }
        catch (Exception deallocateEx)
        {
            logger.LogError(deallocateEx, $"Failed to deallocate VM {vm.Data.Name} after error. Manual intervention required.");
        }
    }
}

// NEW: Helper method to get VM's private IP address
static async Task<string?> GetVMPrivateIpAsync(VirtualMachineResource vm, ILogger logger)
{
    try
    {
        // Create an ArmClient to access Azure resources
        var credential = new DefaultAzureCredential();
        var armClient = new ArmClient(credential);
        
        var firstNetworkInterface = vm.Data.NetworkProfile.NetworkInterfaces.FirstOrDefault();
        if (firstNetworkInterface != null)
        {
            var nicId = firstNetworkInterface.Id;
            var nicResource = armClient.GetNetworkInterfaceResource(nicId);
            
            // Refresh to ensure we have the latest data
            var refreshedNicResponse = await nicResource.GetAsync();
            var refreshedNic = refreshedNicResponse.Value;
            
            // Get the IP configuration
            var ipConfig = refreshedNic.Data.IPConfigurations.FirstOrDefault();
            return ipConfig?.PrivateIPAddress;
        }
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, $"Error retrieving private IP for VM {vm.Data.Name}");
    }
    
    return null;
}

// NEW: Helper method to test RDP connectivity
static async Task<bool> WaitForRdpServiceAsync(string ipAddress, int maxAttempts, int attemptDelaySeconds, ILogger logger)
{
    logger.LogInformation($"Testing RDP connectivity to {ipAddress}...");
    
    for (int attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            using var tcpClient = new TcpClient();
            // Use short timeout for connection attempts
            var connectTask = tcpClient.ConnectAsync(ipAddress, 3389);
            
            // Wait at most 5 seconds for connection
            if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask)
            {
                logger.LogInformation($"RDP port is responding on attempt {attempt}.");
                return true;
            }
            
            logger.LogInformation($"RDP connection attempt {attempt}/{maxAttempts} timed out.");
        }
        catch (Exception ex)
        {
            logger.LogInformation($"RDP connection attempt {attempt}/{maxAttempts} failed: {ex.GetType().Name}");
        }
        
        // Only delay if we're not on the last attempt
        if (attempt < maxAttempts)
        {
            await Task.Delay(TimeSpan.FromSeconds(attemptDelaySeconds));
        }
    }
    
    return false;
}

// NEW: Helper method to run initialization script on VM
static async Task RunInitializationScriptAsync(VirtualMachineResource vm, ILogger logger)
{
    try
    {
        // Create PowerShell script that checks and initializes key services
        string initScript = @"
# Initialization script to ensure all key services are running
$servicesToCheck = @(
    'TermService',       # Remote Desktop Service
    'LanmanServer',      # Server service (file sharing)
    'Browser',           # Computer Browser service
    'Dnscache',          # DNS Client service
    'BITS',              # Background Intelligent Transfer Service
    'wuauserv'           # Windows Update service
)

# Initialize services
foreach ($serviceName in $servicesToCheck) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Running') {
                Write-Output ""Starting service: $serviceName...""
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                $status = (Get-Service -Name $serviceName).Status
                Write-Output ""Service $serviceName status: $status""
            } else {
                Write-Output ""Service $serviceName is already running.""
            }
        } else {
            Write-Output ""Service $serviceName not found.""
        }
    } catch {
        Write-Output ""Error checking/starting service $serviceName: $_""
    }
}

# Execution a few common commands to ensure system components are initialized
Write-Output ""Running basic system commands for initialization...""
$null = ipconfig /all
$null = Get-ComputerInfo
$null = Get-WmiObject -Class Win32_LogicalDisk
$null = Get-Process

# Flush DNS cache
ipconfig /flushdns

# Optimize for next startup
Write-Output ""Optimizing for next startup...""
Write-Output ""Done with initialization.""
";

        // Create the command input
        var runCommandInput = new RunCommandInput("RunPowerShellScript");
        runCommandInput.Script.Add(initScript);

        // Execute the script
        logger.LogInformation($"Executing initialization script on VM {vm.Data.Name}...");
        var result = await vm.RunCommandAsync(Azure.WaitUntil.Completed, runCommandInput);
        
        // Log the output
        if (result?.Value?.Value != null)
        {
            foreach (var output in result.Value.Value)
            {
                logger.LogInformation($"Initialization output for VM {vm.Data.Name}: {output.Message}");
            }
        }
        
        logger.LogInformation($"Initialization script completed on VM {vm.Data.Name}");
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, $"Failed to run initialization script on VM {vm.Data.Name}. Continuing with warm-up process.");
    }
}

// NEW: Helper method to run final verification before deallocating
static async Task RunFinalVerificationAsync(VirtualMachineResource vm, ILogger logger)
{
    try
    {
        // Create PowerShell script for final verification
        string verifyScript = @"
# Final verification script
Write-Output ""Running final verification...""

# Check RDP service status
$rdpService = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
if ($rdpService -and $rdpService.Status -eq 'Running') {
    Write-Output ""✓ RDP service is running correctly.""
} else {
    Write-Error ""RDP service is not in the expected state.""
}

# Check the Windows Update service (important for a clean system state)
$wuService = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
if ($wuService) {
    Write-Output ""✓ Windows Update service state: $($wuService.Status)""
}

# Report system uptime (useful for diagnosing long boot times)
$os = Get-WmiObject win32_operatingsystem
$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
Write-Output ""✓ System uptime: $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s""

# Report available memory
$computerSystem = Get-CimInstance CIM_ComputerSystem
$totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
Write-Output ""✓ Total memory: $totalMemoryGB GB""

# Final verification complete
Write-Output ""Final verification complete. VM ready for deallocation.""
";

        // Create the command input
        var verifyCommandInput = new RunCommandInput("RunPowerShellScript");
        verifyCommandInput.Script.Add(verifyScript);

        // Execute the script
        logger.LogInformation($"Running final verification on VM {vm.Data.Name}...");
        var result = await vm.RunCommandAsync(Azure.WaitUntil.Completed, verifyCommandInput);
        
        // Log the output
        if (result?.Value?.Value != null)
        {
            foreach (var output in result.Value.Value)
            {
                logger.LogInformation($"Verification output for VM {vm.Data.Name}: {output.Message}");
            }
        }
        
        logger.LogInformation($"Final verification completed on VM {vm.Data.Name}");
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, $"Failed to run verification script on VM {vm.Data.Name}. Continuing with deallocation.");
    }
}

// --- Host Startup ---
try
{
    // Wait for the potentially long-running initialization task to complete
    Console.WriteLine("Main thread: Waiting for VM Pool initialization task to complete...");
    initializePoolTask.Wait(); // This blocks the current thread.
    Console.WriteLine("Main thread: VM Pool initialization task has completed.");
    
    if (initializePoolTask.IsFaulted)
    {
        Console.Error.WriteLine("Main thread: VM Pool initialization task failed with errors (see logs above).");
        // Log the exception but don't re-throw to allow the app to start
        if (initializePoolTask.Exception != null)
        {
            Console.Error.WriteLine($"Error details: {initializePoolTask.Exception.InnerException?.Message ?? "Unknown error"}");
        }
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Main thread: An error occurred while waiting for the VM pool initialization task: {ex}");
    // Continue execution to start the host
}

Console.WriteLine("Main thread: Building Azure Functions host...");
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(services => {
        // You can add additional service registrations here
    })
    .Build();

Console.WriteLine("Main thread: Starting Azure Functions host...");
host.Run();

Console.WriteLine("Main thread: Azure Functions host has shut down.");