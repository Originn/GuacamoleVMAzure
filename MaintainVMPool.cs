using System;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

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
                
                // Ensure we maintain the pool size on startup
                logger.LogInformation("Ensuring minimum pool size is maintained during initialization...");
                await poolManager.EnsurePoolSizeAsync();
                
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