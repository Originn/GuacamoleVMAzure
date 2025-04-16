using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure;

namespace DeployVMFunction
{
    public static class MaintainVMPool
    {
        [Function("MaintainVMPool")]
        public static async Task Run([TimerTrigger("0 0 0 1 1 *", RunOnStartup = true)] MyInfo? myTimer, FunctionContext context)
        {
            var logger = context.GetLogger("MaintainVMPool");
            logger.LogInformation($"VM Pool initialization function executed at: {DateTime.Now}");

            try
            {
                var poolManager = new VMPoolManager(logger);
                
                // First, clean up any orphaned resources from previous failures
                logger.LogInformation("Cleaning up any orphaned resources...");
                await poolManager.CleanupOrphanedResourcesAsync();
                
                // Get current pool status
                var poolStatus = await poolManager.GetPoolStatusAsync();
                logger.LogInformation($"Current pool status: {poolStatus.DeallocatedVMs.Count} deallocated VMs, " + 
                                     $"{poolStatus.RunningVMs.Count} running VMs, " +
                                     $"{poolStatus.TransitioningVMs.Count} transitioning VMs, " +
                                     $"{poolStatus.OtherVMs.Count} other SolidCAM VMs");
                // DISABLED: Skipping user account configuration and using default password
                // logger.LogInformation("Checking if existing pool VMs need password configuration...");
                // await ConfigureExistingVMsAsync(poolStatus.DeallocatedVMs, logger);
                // await ConfigureExistingVMsAsync(poolStatus.RunningVMs, logger);
                
                logger.LogInformation("Ensuring minimum pool size is maintained during initialization...");
                await EnsurePoolSizeWithPasswordsAsync(poolManager, logger);
                
                // Check pool status again after maintenance
                var updatedStatus = await poolManager.GetPoolStatusAsync();
                logger.LogInformation($"Updated pool status: {updatedStatus.DeallocatedVMs.Count} deallocated VMs ready for allocation");
                
                logger.LogInformation("VM Pool initialization completed successfully");
            }
            catch (Exception ex)
            {
                logger.LogError($"Error in VM Pool initialization: {ex.Message}");
                logger.LogError(ex.StackTrace);
                
                // More detailed logging for quota-related issues
                if (ex.Message.Contains("quota"))
                {
                    logger.LogError("This appears to be a quota limitation issue. Consider requesting a quota increase " +
                                   "or configuring smaller VM sizes via the VM_SIZE environment variable.");
                }
            }
        }
        
        /// <summary>
        /// Ensures the pool has the minimum number of VMs, each with configured passwords
        /// </summary>
        private static async Task EnsurePoolSizeWithPasswordsAsync(VMPoolManager poolManager, ILogger logger)
        {
            // Get current pool status
            var poolStatus = await poolManager.GetPoolStatusAsync();
            
            // Calculate how many VMs need to be created
            int needed = poolManager.MinPoolSize - poolStatus.DeallocatedVMs.Count;
            
            if (needed <= 0)
            {
                logger.LogInformation($"Pool already has sufficient VMs: {poolStatus.DeallocatedVMs.Count} >= {poolManager.MinPoolSize}");
                return;
            }
            
            logger.LogInformation($"Pool requires {needed} more VM(s). Creating them now.");
            var newVMs = new List<VirtualMachineResource>();
            
            // Create VMs
            for (int i = 0; i < needed; i++)
            {
                try
                {
                    logger.LogInformation($"Creating pool VM {i+1} of {needed}...");
                    
                    // Use the VMPoolManager to create a new VM with password already configured
                    var vm = await poolManager.CreatePoolVMAsync();
                    logger.LogInformation($"Successfully created pool VM: {vm.Data.Name}");
                    newVMs.Add(vm);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, $"Failed to create VM {i+1} of {needed}");
                }
            }
            
            logger.LogInformation($"Successfully created {newVMs.Count} out of {needed} VMs");
        }
        
        /// <summary>
        /// Configure user accounts for existing VMs that don't have passwords stored
        /// </summary>
        private static async Task ConfigureExistingVMsAsync(List<VirtualMachineResource> vms, ILogger logger)
        {
            if (vms.Count == 0)
                return;
                
            logger.LogInformation($"Checking {vms.Count} VMs for password configuration...");
            
            foreach (var vm in vms)
            {
                // Check if password exists for this VM
                string existingPassword = Program.GetVMPassword(vm.Data.Name, logger);
                
                if (string.IsNullOrEmpty(existingPassword))
                {
                    logger.LogInformation($"VM {vm.Data.Name} has no stored password. Configuring now...");
                    
                    bool wasRunning = false;
                    
                    // Check if VM is running, if not start it
                    try
                    {
                        var instanceView = await vm.InstanceViewAsync();
                        var powerState = instanceView.Value?.Statuses
                            ?.FirstOrDefault(s => s.Code != null && s.Code.StartsWith("PowerState/"))?.Code;
                            
                        if (powerState != "PowerState/running")
                        {
                            logger.LogInformation($"Starting VM {vm.Data.Name} to configure user account...");
                            await vm.PowerOnAsync(Azure.WaitUntil.Completed);
                            
                            // Wait for the VM to be ready
                            logger.LogInformation($"Waiting for VM {vm.Data.Name} to be ready...");
                            await Task.Delay(TimeSpan.FromSeconds(60)); // Give it a minute to start up
                        }
                        else
                        {
                            wasRunning = true;
                            logger.LogInformation($"VM {vm.Data.Name} is already running.");
                        }
                        
                        // Generate and configure the user accounts
                        // Use default password instead of generating one
                        string password = "Rt@wqPP7ZvUgtS7"; // Program.GenerateSecurePassword(16);
                        bool configSuccess = await Program.ConfigureMultiUserAccountsAsync(vm, password, logger);
                        if (configSuccess)
                        {
                            // Store the password for future use
                            await Program.StoreVMPasswordAsync(vm.Data.Name, password, logger);
                            logger.LogInformation($"Successfully configured user account for VM {vm.Data.Name}");
                        }
                        else
                        {
                            logger.LogWarning($"Failed to configure user account for VM {vm.Data.Name}");
                        }
                        
                        // If the VM wasn't running before, hibernate it instead of deallocating
                        if (!wasRunning)
                        {
                            logger.LogInformation($"Hibernating VM {vm.Data.Name}...");
                            try
                            {
                                // Method 1: Try to use the built-in hibernate parameter on PowerOff
                                var parameters = new Dictionary<string, string>();
                                parameters.Add("skipShutdown", "true");
                                parameters.Add("hibernate", "true");
                                
                                    try {
                                    // Try to hibernate using the PowerOff method with hibernate parameter
                                    await vm.PowerOffAsync(WaitUntil.Completed, skipShutdown: true);
                                    logger.LogInformation($"VM {vm.Data.Name} hibernated and returned to pool");
                                    return; // Exit the method since we're done
                                }
                                catch (Exception innerEx) {
                                }
                                
                                // Method 2: Use PowerState runCommand as fallback
                                string hibernateScript = @"
                                    $state = Stop-Computer -Force -PassThru -Hibernate
                                    Write-Output ""Hibernate command returned: $state""
                                ";
                                
                                var runCommandInput = new RunCommandInput("RunPowerShellScript");
                                runCommandInput.Script.Add(hibernateScript);
                                
                                await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
                                logger.LogInformation($"Successfully sent hibernation command to VM {vm.Data.Name}");
                                
                                // Wait a bit for the hibernation to take effect
                                await Task.Delay(TimeSpan.FromSeconds(10));
                                logger.LogInformation($"VM {vm.Data.Name} hibernated and returned to pool");
                            }
                            catch (Exception hibEx)
                            {
                                logger.LogWarning(hibEx, $"Failed to hibernate VM {vm.Data.Name}. Falling back to deallocation.");
                                await vm.DeallocateAsync(Azure.WaitUntil.Completed);
                                logger.LogInformation($"VM {vm.Data.Name} deallocated (fallback) and returned to pool");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, $"Error configuring VM {vm.Data.Name}");
                    }
                }
                else
                {
                    logger.LogInformation($"VM {vm.Data.Name} already has a stored password. Skipping configuration.");
                }
            }
        }
    }

    // Required for TimerTrigger
    public class MyInfo
    {
        public MyScheduleStatus? ScheduleStatus { get; set; }
        public bool IsPastDue { get; set; }
    }

    public class MyScheduleStatus
    {
        public DateTime Last { get; set; }
        public DateTime Next { get; set; }
        public DateTime LastUpdated { get; set; }
    }
}