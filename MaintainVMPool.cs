using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Azure.ResourceManager.Compute;

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
                
                // Check for VMs without configured passwords
                logger.LogInformation("Checking if existing pool VMs need password configuration...");
                await ConfigureExistingVMsAsync(poolStatus.DeallocatedVMs, logger);
                await ConfigureExistingVMsAsync(poolStatus.RunningVMs, logger);
                
                // Ensure we maintain the pool size on startup
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
                    
                    // Use the VMPoolManager to create a new VM
                    var vm = await poolManager.CreatePoolVMAsync();
                    logger.LogInformation($"Successfully created pool VM: {vm.Data.Name}");
                    
                    // Before deallocating, we need to start the VM to configure the user account
                    logger.LogInformation($"Starting VM {vm.Data.Name} to configure user account...");
                    await vm.PowerOnAsync(Azure.WaitUntil.Completed);
                    
                    // Wait for the VM to be ready
                    logger.LogInformation($"Waiting for VM {vm.Data.Name} to be ready...");
                    await Task.Delay(TimeSpan.FromSeconds(60)); // Give it a minute to start up
                    
                    // Generate and configure the user account
                    string password = Program.GenerateSecurePassword(16);
                    bool configSuccess = await Program.ConfigureVMUserAccountAsync(vm, password, logger);
                    
                    if (configSuccess)
                    {
                        // Store the password for future use
                        await Program.StoreVMPasswordAsync(vm.Data.Name, password, logger);
                        logger.LogInformation($"Successfully configured user account for VM {vm.Data.Name}");
                        newVMs.Add(vm);
                    }
                    else
                    {
                        logger.LogWarning($"Failed to configure user account for VM {vm.Data.Name}");
                    }
                    
                    // Deallocate the VM to return it to the pool
                    logger.LogInformation($"Deallocating VM {vm.Data.Name}...");
                    await vm.DeallocateAsync(Azure.WaitUntil.Completed);
                    logger.LogInformation($"VM {vm.Data.Name} deallocated and added to pool");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, $"Failed to create VM {i+1} of {needed}");
                }
            }
            
            logger.LogInformation($"Successfully created and configured {newVMs.Count} out of {needed} VMs");
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
                        
                        // Generate and configure the user account
                        string password = Program.GenerateSecurePassword(16);
                        bool configSuccess = await Program.ConfigureVMUserAccountAsync(vm, password, logger);
                        
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
                        
                        // If the VM wasn't running before, deallocate it
                        if (!wasRunning)
                        {
                            logger.LogInformation($"Deallocating VM {vm.Data.Name}...");
                            await vm.DeallocateAsync(Azure.WaitUntil.Completed);
                            logger.LogInformation($"VM {vm.Data.Name} deallocated and returned to pool");
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