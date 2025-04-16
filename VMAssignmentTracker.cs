using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Azure.Data.Tables;
using Azure;
using Azure.ResourceManager.Compute;

namespace DeployVMFunction
{
    /// <summary>
    /// Tracks VM and user account assignments across function instances
    /// </summary>
    public class VMAssignmentTracker
    {
        private readonly ILogger _logger;
        private readonly TableClient _tableClient;
        private const string TABLE_NAME = "VMAssignments";
        private const int MAX_ACCOUNTS_PER_VM = 3;

        private class VMAssignmentEntity : ITableEntity
        {
            // PartitionKey = VM Name
            // RowKey = "assignment"
            public string PartitionKey { get; set; }
            public string RowKey { get; set; }
            public DateTimeOffset? Timestamp { get; set; }
            public ETag ETag { get; set; }
            
            // Count of how many accounts are assigned on this VM (1-3)
            public int AssignedAccounts { get; set; }
            
            // Timestamp of last assignment to track age
            public DateTimeOffset LastAssignmentTime { get; set; }
            
            // Individual account assignments (1=assigned, 0=available)
            public int Account1Assigned { get; set; }
            public int Account2Assigned { get; set; }
            public int Account3Assigned { get; set; }
            
            // VM IP address for quicker lookups
            public string VMPrivateIP { get; set; }
        }

        public VMAssignmentTracker(ILogger logger, string storageConnectionString)
        {
            _logger = logger;
            
            try
            {
                // Create table client
                var tableServiceClient = new TableServiceClient(storageConnectionString);
                _tableClient = tableServiceClient.GetTableClient(TABLE_NAME);
                
                // Ensure table exists
                _tableClient.CreateIfNotExists();
                _logger.LogInformation($"Initialized VM Assignment Tracker with table {TABLE_NAME}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error initializing VM Assignment Tracker: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Finds a running VM with available user accounts or returns null if none found
        /// </summary>
        public async Task<(VirtualMachineResource vm, string privateIp, int accountNumber)?> FindVMWithAvailableAccountAsync(
            List<VirtualMachineResource> runningVMs)
        {
            try
            {
                _logger.LogInformation($"Looking for VM with available accounts among {runningVMs.Count} running VMs");
                
                // If no running VMs, return null
                if (runningVMs.Count == 0)
                {
                    _logger.LogInformation("No running VMs available, need to allocate new VM");
                    return null;
                }
                
                // Check each VM's assignment status
                foreach (var vm in runningVMs)
                {
                    string vmName = vm.Data.Name;
                    
                    // Get assignment record for this VM
                    try
                    {
                        var response = await _tableClient.GetEntityAsync<VMAssignmentEntity>(vmName, "assignment");
                        var entity = response.Value;
                        
                        _logger.LogInformation($"Found VM assignment record for {vmName}, has {entity.AssignedAccounts}/{MAX_ACCOUNTS_PER_VM} accounts assigned");
                        
                        // Check if this VM has available accounts
                        if (entity.AssignedAccounts < MAX_ACCOUNTS_PER_VM)
                        {
                            // Find the first available account number
                            int accountNumber = 0;
                            if (entity.Account1Assigned == 0) accountNumber = 1;
                            else if (entity.Account2Assigned == 0) accountNumber = 2;
                            else if (entity.Account3Assigned == 0) accountNumber = 3;
                            
                            if (accountNumber == 0)
                            {
                                _logger.LogWarning($"VM {vmName} shows {entity.AssignedAccounts} assigned accounts but no available account found. Repairing record.");
                                // Reset the record since it's inconsistent
                                entity.AssignedAccounts = MAX_ACCOUNTS_PER_VM;
                                entity.Account1Assigned = 1;
                                entity.Account2Assigned = 1;
                                entity.Account3Assigned = 1;
                                await _tableClient.UpdateEntityAsync(entity, ETag.All);
                                continue;
                            }
                            
                            // Return the VM, IP, and account number
                            return (vm, entity.VMPrivateIP, accountNumber);
                        }
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        // VM doesn't have an assignment record yet, it's fully available
                        _logger.LogInformation($"VM {vmName} doesn't have assignment record yet, assuming all accounts available");
                        
                        // We'll create a record later when assigning the first account
                        return (vm, null, 1); // Null IP will be filled in during assignment
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"Error checking assignment status for VM {vmName}, skipping.");
                    }
                }
                
                _logger.LogInformation("No VM with available accounts found among running VMs");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error finding VM with available accounts");
                throw;
            }
        }

        /// <summary>
        /// Assigns a user account on a VM and returns the account name
        /// </summary>
        public async Task<string> AssignAccountOnVMAsync(VirtualMachineResource vm, string vmPrivateIp, int accountNumber)
        {
            string vmName = vm.Data.Name;
            _logger.LogInformation($"Assigning account #{accountNumber} on VM {vmName}");
            
            try
            {
                VMAssignmentEntity entity;
                bool isNewEntity = false;
                
                try
                {
                    // Try to get existing record
                    var response = await _tableClient.GetEntityAsync<VMAssignmentEntity>(vmName, "assignment");
                    entity = response.Value;
                    _logger.LogInformation($"Found existing assignment record for VM {vmName}");
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    // Create new record
                    _logger.LogInformation($"Creating new assignment record for VM {vmName}");
                    entity = new VMAssignmentEntity
                    {
                        PartitionKey = vmName,
                        RowKey = "assignment",
                        AssignedAccounts = 0,
                        Account1Assigned = 0,
                        Account2Assigned = 0,
                        Account3Assigned = 0,
                        LastAssignmentTime = DateTimeOffset.UtcNow,
                        VMPrivateIP = vmPrivateIp
                    };
                    isNewEntity = true;
                }
                
                // Mark the specified account as assigned
                switch (accountNumber)
                {
                    case 1:
                        entity.Account1Assigned = 1;
                        break;
                    case 2:
                        entity.Account2Assigned = 1;
                        break;
                    case 3:
                        entity.Account3Assigned = 1;
                        break;
                    default:
                        throw new ArgumentException($"Invalid account number: {accountNumber}");
                }
                
                // Update counts and timestamp
                entity.AssignedAccounts++;
                entity.LastAssignmentTime = DateTimeOffset.UtcNow;
                
                // Update IP if needed
                if (string.IsNullOrEmpty(entity.VMPrivateIP) && !string.IsNullOrEmpty(vmPrivateIp))
                {
                    entity.VMPrivateIP = vmPrivateIp;
                }
                
                // Save the entity
                if (isNewEntity)
                {
                    await _tableClient.AddEntityAsync(entity);
                }
                else
                {
                    await _tableClient.UpdateEntityAsync(entity, ETag.All);
                }
                
                string username = $"SolidCAMOperator{accountNumber}";
                _logger.LogInformation($"Successfully assigned account {username} on VM {vmName}");
                return username;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error assigning account on VM {vmName}");
                throw;
            }
        }

        /// <summary>
        /// Releases a user account on a VM when the session ends
        /// </summary>
        public async Task ReleaseAccountOnVMAsync(string vmName, int accountNumber)
        {
            try
            {
                _logger.LogInformation($"Releasing account #{accountNumber} on VM {vmName}");
                
                // Get the assignment record
                try
                {
                    var response = await _tableClient.GetEntityAsync<VMAssignmentEntity>(vmName, "assignment");
                    var entity = response.Value;
                    
                    // Mark the account as available
                    switch (accountNumber)
                    {
                        case 1:
                            entity.Account1Assigned = 0;
                            break;
                        case 2:
                            entity.Account2Assigned = 0;
                            break;
                        case 3:
                            entity.Account3Assigned = 0;
                            break;
                    }
                    
                    // Update count
                    entity.AssignedAccounts = Math.Max(0, entity.AssignedAccounts - 1);
                    
                    // Save changes
                    await _tableClient.UpdateEntityAsync(entity, ETag.All);
                    _logger.LogInformation($"Successfully released account #{accountNumber} on VM {vmName}");
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    _logger.LogWarning($"VM {vmName} assignment record not found during release operation");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error releasing account on VM {vmName}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Unhandled error in ReleaseAccountOnVMAsync: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Marks a VM as deleted or unavailable, removing all assignments
        /// </summary>
        public async Task MarkVMAsDeletedAsync(string vmName)
        {
            try
            {
                _logger.LogInformation($"Marking VM {vmName} as deleted/unavailable");
                
                try
                {
                    // Delete the assignment record if it exists
                    await _tableClient.DeleteEntityAsync(vmName, "assignment", ETag.All);
                    _logger.LogInformation($"Removed assignment record for VM {vmName}");
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    _logger.LogInformation($"No assignment record found for VM {vmName} during deletion");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error marking VM {vmName} as deleted");
            }
        }
    }
}
