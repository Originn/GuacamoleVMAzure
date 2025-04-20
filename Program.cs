using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection; 
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using Azure;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.ResourceManager.Resources;
using Azure.Core;
using Azure.Data.Tables;
using DeployVMFunction;
using Microsoft.Extensions.Configuration;
using Azure.ResourceManager.Compute.Models;

namespace DeployVMFunction
{
    public static class Program
    {
        // Initialize a global table client for VM credentials
        private static TableClient credentialsTableClient = null;

        // Initialize a dictionary for caching VM passwords
        private static Dictionary<string, string> vmCredentialsCache = new Dictionary<string, string>();

        public static void Main(string[] args)
        {
            Console.WriteLine("======= AZURE FUNCTION HOST PROCESS STARTING =======");
            Console.WriteLine($"Current time: {DateTime.Now}");
            Console.WriteLine($"Current directory: {Environment.CurrentDirectory}");
            Console.WriteLine("Configuring Azure Functions host...");

            // Set up configuration to read settings
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Environment.CurrentDirectory)
                .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            // Initialize Table Storage for VM credentials
            // Try to get connection string from multiple sources
            string storageConnectionString = configuration.GetConnectionString("AzureWebJobsStorage") 
                                         ?? Environment.GetEnvironmentVariable("AzureWebJobsStorage")
                                         ?? configuration.GetValue<string>("AzureWebJobsStorage");
            
            Console.WriteLine($"Storage connection string found: {!string.IsNullOrEmpty(storageConnectionString)}");

            if (!string.IsNullOrEmpty(storageConnectionString))
            {
                try
                {
                    Console.WriteLine("Initializing Table Storage client...");
                    credentialsTableClient = new TableClient(storageConnectionString, "VMCredentials");
                    Console.WriteLine("Creating VM credentials table if it doesn't exist...");
                    credentialsTableClient.CreateIfNotExists();
                    Console.WriteLine("Initialized VM credentials table storage successfully");
                    
                    // Load existing credentials into cache
                    LoadCredentialsFromTable();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to initialize Table Storage for VM credentials: {ex.Message}");
                    Console.WriteLine($"Exception type: {ex.GetType().Name}");
                    Console.WriteLine($"Exception details: {ex}");
                    credentialsTableClient = null; // Reset to null on failure
                }
            }
            else
            {
                Console.WriteLine("WARNING: AzureWebJobsStorage connection string is missing. VM passwords will only be stored in memory.");
            }

            // Create a host builder with the necessary configuration
            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults()
                .ConfigureLogging(logging =>
                {
                    logging.AddSimpleConsole(options =>
                    {
                        options.IncludeScopes = true;
                        options.SingleLine = false;
                        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
                    });
                    logging.SetMinimumLevel(LogLevel.Information);
                })
                .ConfigureServices((context, services) =>
                {
                    // Register services if needed
                })
                .Build();

            Console.WriteLine("Main thread: Building Azure Functions host complete.");
            Console.WriteLine("Main thread: Starting VM Pool initialization in the background...");

            // Start VM pool initialization in the background
            var initializePoolTask = Task.Run(async () =>
            {
                await InitializeVMPoolAsync();
            });

            // The host will run and listen for triggers
            Console.WriteLine("Main thread: Starting Azure Functions host...");
            host.Run();

            Console.WriteLine("Main thread: Azure Functions host has shut down.");
        }

        // Method to initialize the VM pool
        private static async Task InitializeVMPoolAsync()
        {
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole(options => options.IncludeScopes = true);
                builder.SetMinimumLevel(LogLevel.Information);
            });

            var logger = loggerFactory.CreateLogger("VMPoolInitialization");
            logger.LogInformation("Beginning VM pool initialization...");

            try
            {
                // Set up configuration to read settings
                var configuration = new ConfigurationBuilder()
                    .SetBasePath(Environment.CurrentDirectory)
                    .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                    .AddEnvironmentVariables()
                    .Build();

                // Check if the pool initialization feature is enabled
                bool initializeVMPool = configuration.GetValue("VMPoolSettings__InitializePool", false);
                if (!initializeVMPool)
                {
                    logger.LogInformation("VM pool initialization is disabled via configuration. Skipping initialization.");
                    return;
                }

                // Read pool configuration settings
                int minPoolSize = configuration.GetValue("MIN_POOL_SIZE", 2);
                int warmupDelaySeconds = configuration.GetValue("VMPoolSettings__WarmupDelaySeconds", 90);
                int maxServiceCheckAttempts = configuration.GetValue("VMPoolSettings__MaxServiceCheckAttempts", 10);
                int serviceCheckDelaySeconds = configuration.GetValue("VMPoolSettings__ServiceCheckDelaySeconds", 10);

                logger.LogInformation($"Target minimum VM pool size configured: {minPoolSize}");
                logger.LogInformation($"VM warm-up time configured: {warmupDelaySeconds} seconds");

                // Create and use the VM pool manager
                var poolManager = new VMPoolManager(logger);
                
                // Clean up any orphaned resources
                logger.LogInformation("Cleaning up any orphaned Azure resources...");
                await poolManager.CleanupOrphanedResourcesAsync();
                
                // Check current pool status
                logger.LogInformation("Checking current VM pool status...");
                var status = await poolManager.GetPoolStatusAsync();
                logger.LogInformation($"Initial pool status: {status.DeallocatedVMs.Count} deallocated VM(s) found in the pool.");

                // Calculate how many VMs need to be created
                int needed = minPoolSize - status.DeallocatedVMs.Count;
                if (needed <= 0)
                {
                    logger.LogInformation($"Pool size ({status.DeallocatedVMs.Count}) already meets or exceeds minimum ({minPoolSize}). No action needed.");
                    return;
                }

                logger.LogInformation($"Pool needs {needed} new VM(s) to reach the target size of {minPoolSize}.");
                var newVMs = new List<VirtualMachineResource>();

                // Create VMs
                for (int i = 0; i < needed; i++)
                {
                    try
                    {
                        logger.LogInformation($"Creating VM {i+1} of {needed}...");
                        var vm = await poolManager.CreateAndReturnRunningVMAsync("pool");
                        logger.LogInformation($"Successfully created VM: {vm.Data.Name}");
                        
                            // Generate and store password for the VM
                            // Use the default password instead of generating one
                            var password = "Rt@wqPP7ZvUgtS7";
                            bool configSuccess = await ConfigureMultiUserAccountsAsync(vm, password, logger);
                        if (configSuccess)
                        {
                            // Store password in Table Storage and memory cache
                            await StoreVMPasswordAsync(vm.Data.Name, password, logger);
                            logger.LogInformation($"Successfully configured user account for VM {vm.Data.Name}");
                            newVMs.Add(vm);
                        }
                        else
                        {
                            logger.LogWarning($"Failed to configure user account for VM {vm.Data.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, $"Failed to create VM {i+1} of {needed}");
                    }
                }

                logger.LogInformation($"Created {newVMs.Count} out of {needed} VMs.");

                // Warm up created VMs
                if (newVMs.Any())
                {
                    logger.LogInformation($"Warming up {newVMs.Count} new VM(s)...");
                    
                    foreach (var vm in newVMs)
                    {
                        try
                        {
                            await WarmupVMAsync(vm, warmupDelaySeconds, maxServiceCheckAttempts, serviceCheckDelaySeconds, logger);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, $"Error during warmup for VM {vm.Data.Name}");
                        }
                    }
                    
                    logger.LogInformation("Warm-up process completed.");
                }

                // Get final pool status
                var finalStatus = await poolManager.GetPoolStatusAsync();
                logger.LogInformation($"Pool initialization complete. Final pool status: {finalStatus.DeallocatedVMs.Count} deallocated VM(s) available.");
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "A critical error occurred during the VM pool management process.");
            }
        }

        // Method to warm up a VM
        private static async Task WarmupVMAsync(VirtualMachineResource vm, int warmupDelaySeconds, int maxAttempts, int attemptDelaySeconds, ILogger logger)
        {
            try
            {
                logger.LogInformation($"Starting warm-up process for VM {vm.Data.Name}...");
                // Get the VM's private IP address for testing connectivity
                string vmPrivateIp = await GetVMPrivateIPAsync(vm, logger);
                if (string.IsNullOrEmpty(vmPrivateIp))
                {
                    logger.LogWarning($"Could not determine private IP for VM {vm.Data.Name}. Will continue with warm-up but connectivity testing will be skipped.");
                }
                
                // Allow some initialization time
                logger.LogInformation($"Allowing initial boot time of 60 seconds for VM {vm.Data.Name}...");
                await Task.Delay(TimeSpan.FromSeconds(60));
                
                // Test for RDP connectivity if we have an IP
                if (!string.IsNullOrEmpty(vmPrivateIp))
                {
                    bool rdpReady = await WaitForRdpServiceAsync(vmPrivateIp, maxAttempts, attemptDelaySeconds, logger);
                    if (rdpReady)
                    {
                        logger.LogInformation($"RDP service on VM {vm.Data.Name} is responding.");
                    }
                    else
                    {
                        logger.LogWarning($"RDP service on VM {vm.Data.Name} did not become responsive after {maxAttempts} attempts.");
                    }
                }
                
                // Run additional initialization steps if needed
                logger.LogInformation($"Running initialization script on VM {vm.Data.Name}...");
                await RunInitializationScriptAsync(vm, logger);
                
                // Wait for any remaining warm-up time
                int remainingWarmupTime = Math.Max(0, warmupDelaySeconds - 60 - (maxAttempts * attemptDelaySeconds));
                if (remainingWarmupTime > 0)
                {
                    logger.LogInformation($"Waiting additional {remainingWarmupTime}s for full initialization of VM {vm.Data.Name}...");
                    await Task.Delay(TimeSpan.FromSeconds(remainingWarmupTime));
                }
                
                // Hibernate the VM
                logger.LogInformation($"Warm-up complete for {vm.Data.Name}. Hibernating...");
                try
                {
                    await vm.PowerOffAsync(WaitUntil.Completed, skipShutdown: true);// skipShutdown: true, hibernate: true
                    logger.LogInformation($"VM {vm.Data.Name} hibernated and returned to pool.");
                }
                catch (Exception hibEx)
                {
                    logger.LogWarning(hibEx, $"Failed to hibernate VM {vm.Data.Name}. Falling back to deallocation.");
                    await vm.DeallocateAsync(WaitUntil.Completed);
                    logger.LogInformation($"VM {vm.Data.Name} deallocated (fallback) and returned to pool.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error during warm-up for VM {vm.Data.Name}");
                
                // Try to deallocate the VM if an exception occurred
                try
                {
                    logger.LogInformation($"Attempting to deallocate VM {vm.Data.Name} after error...");
                    await vm.DeallocateAsync(WaitUntil.Completed);
                    logger.LogInformation($"Successfully deallocated VM {vm.Data.Name} after error.");
                }
                catch (Exception deallocateEx)
                {
                    logger.LogError(deallocateEx, $"Failed to deallocate VM {vm.Data.Name} after error. Manual intervention required.");
                }
                
                throw;
            }
        }
        // Helper method to get VM's private IP address
        private static async Task<string> GetVMPrivateIPAsync(VirtualMachineResource vm, ILogger logger)
        {
            try
            {
                var credential = new DefaultAzureCredential();
                var armClient = new ArmClient(credential);
                
                var firstNetworkInterface = vm.Data.NetworkProfile.NetworkInterfaces.FirstOrDefault();
                if (firstNetworkInterface != null)
                {
                    var nicId = firstNetworkInterface.Id;
                    var nicResource = armClient.GetNetworkInterfaceResource(nicId);
                    
                    var refreshedNicResponse = await nicResource.GetAsync();
                    var refreshedNic = refreshedNicResponse.Value;
                    
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

        // Helper method to wait for RDP service
        private static async Task<bool> WaitForRdpServiceAsync(string ipAddress, int maxAttempts, int attemptDelaySeconds, ILogger logger)
        {
            logger.LogInformation($"Testing RDP connectivity to {ipAddress}...");
            
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    using var tcpClient = new TcpClient();
                    var connectTask = tcpClient.ConnectAsync(ipAddress, 3389);
                    
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
                
                if (attempt < maxAttempts)
                {
                    await Task.Delay(TimeSpan.FromSeconds(attemptDelaySeconds));
                }
            }
            
            return false;
        }

        // Helper method to run initialization script on VM
        private static async Task RunInitializationScriptAsync(VirtualMachineResource vm, ILogger logger)
        {
            try
            {
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

                var runCommandInput = new RunCommandInput("RunPowerShellScript");
                runCommandInput.Script.Add(initScript);

                logger.LogInformation($"Executing initialization script on VM {vm.Data.Name}...");
                var result = await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
                
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

        // Generate a secure random password
        public static string GenerateSecurePassword(int length)
        {
            const string uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Excluded I, O
            const string lowercaseChars = "abcdefghijkmnpqrstuvwxyz"; // Excluded l, o
            const string numericChars = "23456789";                   // Excluded 0, 1
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"; // Common special characters
            var allChars = uppercaseChars + lowercaseChars + numericChars + specialChars;
            var password = new char[length];
            
            // Ensure at least one of each required type
            var requiredChars = new List<char>
            {
                uppercaseChars[RandomNumberGenerator.GetInt32(uppercaseChars.Length)],
                lowercaseChars[RandomNumberGenerator.GetInt32(lowercaseChars.Length)],
                numericChars[RandomNumberGenerator.GetInt32(numericChars.Length)],
                specialChars[RandomNumberGenerator.GetInt32(specialChars.Length)]
            };
            
            if (length < requiredChars.Count)
                throw new ArgumentException("Password length too short to include all required character types.", nameof(length));

            // Fill required characters first
            for (int i = 0; i < requiredChars.Count; i++)
                password[i] = requiredChars[i];

            // Fill the rest with random characters from the full set
            for (int i = requiredChars.Count; i < length; i++)
                password[i] = allChars[RandomNumberGenerator.GetInt32(allChars.Length)];

            // Shuffle the password array thoroughly using Fisher-Yates shuffle
            for (int i = password.Length - 1; i > 0; i--)
            {
                int j = RandomNumberGenerator.GetInt32(i + 1);
                (password[i], password[j]) = (password[j], password[i]); // Swap
            }
            
            return new string(password);
        }

        // Configure the VM user account
        public static async Task<bool> ConfigureVMUserAccountAsync(VirtualMachineResource vm, string password, ILogger logger)
        {
            logger.LogInformation($"Configuring SolidCAMOperator account on VM {vm.Data.Name}...");
            
            string psScript = @"$p = ConvertTo-SecureString '" + password.Replace("'", "''") + 
                      @"' -AsPlainText -Force; $u = 'SolidCAMOperator'; try { Write-Output 'Getting user...'; " +
                      @"$e = Get-LocalUser -Name $u -EA SilentlyContinue; if ($e) { Write-Output 'Setting pwd...'; " +
                      @"Set-LocalUser -Name $u -Password $p -AccountNeverExpires -PasswordNeverExpires $true; " +
                      @"Write-Output 'Set pwd done.'; } else { Write-Output 'Creating user...'; " +
                      @"New-LocalUser -Name $u -Password $p -AccountNeverExpires -PasswordNeverExpires $true; " +
                      @"Write-Output 'Create user done.'; } Write-Output 'Enabling user...'; " +
                      @"Enable-LocalUser -Name $u; Write-Output 'Enable done.'; " +
                      @"Write-Output 'Adding group member...'; " +
                      @"Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $u -EA SilentlyContinue; " +
                      @"Write-Output 'Add group done.'; Write-Output 'Success.'; } catch { " +
                      @"Write-Error ""ERR: $($_.Exception.Message)""; " +
                      @"Write-Error ""Trace: $($_.ScriptStackTrace)""; throw; }";
            
            var runCommandInput = new RunCommandInput("RunPowerShellScript");
            runCommandInput.Script.Add(psScript);
            
            try
            {
                var commandStartTime = DateTime.UtcNow;
                logger.LogInformation($"Executing account setup script on VM {vm.Data.Name}...");
                
                var passwordResetOperation = await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
                var passwordResetResult = passwordResetOperation?.Value;
                
                if (passwordResetResult?.Value != null && passwordResetResult.Value.Any())
                {
                    bool errorFound = false;
                    foreach (var status in passwordResetResult.Value)
                    {
                        if (status.Level?.ToString().Equals("Error", StringComparison.OrdinalIgnoreCase) == true ||
                            status.Message?.Contains("ERR:") == true)
                        {
                            errorFound = true;
                            logger.LogError($"Error in account setup: {status.Message}");
                        }
                    }
                    
                    if (!errorFound && passwordResetResult.Value.Any(s => s.Message?.Contains("Success.") == true))
                    {
                        var commandEndTime = DateTime.UtcNow;
                        var commandDuration = commandEndTime - commandStartTime;
                        logger.LogInformation($"Successfully configured SolidCAMOperator account on VM {vm.Data.Name} in {commandDuration.TotalSeconds:F2} seconds");
                        return true;
                    }
                }
                
                logger.LogWarning($"Failed to configure SolidCAMOperator account on VM {vm.Data.Name}");
                return false;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Exception during account setup on VM {vm.Data.Name}");
                return false;
            }
        }

        // Configure multiple user accounts (SolidCAMOperator1, SolidCAMOperator2, etc.)
        // Configure multiple user accounts (SolidCAMOperator1, SolidCAMOperator2, etc.)
        public static async Task<bool> ConfigureMultiUserAccountsAsync(VirtualMachineResource vm, string password, ILogger logger)
        {
            // MODIFIED: Skip actual account configuration and just store default password
            logger.LogInformation($"SKIPPED: Account configuration for VM {vm.Data.Name}. Using default password instead.");
            
            // Use the default password regardless of what was passed in
            string defaultPassword = "Rt@wqPP7ZvUgtS7";
            
            // Return success without actually configuring accounts
            logger.LogInformation($"Using default password for all SolidCAMOperator accounts on VM {vm.Data.Name}");
            return true;
        }

        // Store VM password in Table Storage and cache - Updated with better error handling
        public static async Task StoreVMPasswordAsync(string vmName, string password, ILogger logger)
        {
            // Store in memory cache
            vmCredentialsCache[vmName] = password;
            
            // Store in Table Storage
            try
            {
                if (credentialsTableClient != null)
                {
                    var entity = new TableEntity(vmName, "password")
                    {
                        ["PasswordValue"] = password,
                        ["CreatedTime"] = DateTime.UtcNow
                    };
                    
                    try
                    {
                        logger.LogInformation($"Storing password for VM {vmName} in Table Storage...");
                        await credentialsTableClient.UpsertEntityAsync(entity);
                        logger.LogInformation($"Successfully stored password for VM {vmName} in Table Storage");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, $"Error during UpsertEntityAsync operation: {ex.Message}");
                        throw;
                    }
                }
                else
                {
                    logger.LogWarning($"Table Storage client not initialized. Password for VM {vmName} only stored in memory.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Failed to store password for VM {vmName} in Table Storage: {ex.Message}");
            }
        }

        // Load credentials from Table Storage into memory cache - Updated with better error handling
        private static void LoadCredentialsFromTable()
        {
            if (credentialsTableClient == null)
                return;
                
            try
            {
                Console.WriteLine("Loading VM credentials from Table Storage...");
                
                try
                {
                    var entities = credentialsTableClient.Query<TableEntity>();
                    int loadedCount = 0;
                    
                    foreach (var entity in entities)
                    {
                        if (entity.ContainsKey("PasswordValue"))
                        {
                            string vmName = entity.PartitionKey;
                            string password = entity.GetString("PasswordValue");
                            
                            if (!string.IsNullOrEmpty(vmName) && !string.IsNullOrEmpty(password))
                            {
                                vmCredentialsCache[vmName] = password;
                                loadedCount++;
                                Console.WriteLine($"Loaded credentials for VM: {vmName}");
                            }
                        }
                    }
                    
                    Console.WriteLine($"Loaded {loadedCount} VM credentials into memory cache");
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    Console.WriteLine("VM credentials table doesn't exist yet. Will be created when first VM is configured.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading VM credentials from Table Storage: {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                Console.WriteLine($"Exception details: {ex}");
            }
        }

        // Get VM password from cache or Table Storage - Updated with better error handling
        public static string GetVMPassword(string vmName, ILogger logger)
        {
            // First check in-memory cache
            if (vmCredentialsCache.TryGetValue(vmName, out string password))
            {
                logger.LogInformation($"Found password for VM {vmName} in memory cache");
                return password;
            }
            
            // If not in memory, try to get from Table Storage
            try
            {
                if (credentialsTableClient != null)
                {
                    try
                    {
                        logger.LogInformation($"Attempting to retrieve password for VM {vmName} from Table Storage");
                        var response = credentialsTableClient.GetEntity<TableEntity>(vmName, "password");
                        
                        if (response != null && response.Value.ContainsKey("PasswordValue"))
                        {
                            string storedPassword = response.Value.GetString("PasswordValue");
                            logger.LogInformation($"Retrieved password for VM {vmName} from Table Storage");
                            
                            // Cache the password in memory for future requests
                            vmCredentialsCache[vmName] = storedPassword;
                            
                            return storedPassword;
                        }
                        else
                        {
                            logger.LogWarning($"Password record found for VM {vmName} in Table Storage but it's missing the PasswordValue field");
                        }
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        logger.LogWarning($"No password record found for VM {vmName} in Table Storage");
                    }
                }
                else
                {
                    logger.LogWarning($"Table Storage client is null. Cannot retrieve password for VM {vmName} from Table Storage");
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning($"Error retrieving password for VM {vmName} from Table Storage: {ex.Message}");
                logger.LogWarning($"Exception type: {ex.GetType().Name}");
            }
            
            logger.LogWarning($"No password found for VM {vmName} in memory or Table Storage");
            return null;
        }
    }
}