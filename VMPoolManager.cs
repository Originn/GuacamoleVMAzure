using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.Core;
using Azure;


namespace DeployVMFunction
{
    public class VMPoolManager
    {
        private readonly string _storageConnectionString;
        private readonly ILogger _logger;
        private readonly ArmClient _armClient;
        private readonly ResourceGroupResource _resourceGroup;
        private readonly string _vnetName;
        private readonly string _subnetName;
        private readonly string _galleryImageId;
        private readonly string _guacamoleServerPrivateIp;
        private AzureLocation _location;
        private readonly int _minPoolSize;
        private readonly List<VirtualMachineSizeType> _vmSizeFallbackOptions;
        private readonly List<AzureLocation> _locationFallbackOptions;
        private VirtualMachineSizeType _vmSize;

        public int MinPoolSize => _minPoolSize;

        public VMPoolManager(ILogger logger)
        {
            _logger = logger;
            _storageConnectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage") ?? 
                throw new InvalidOperationException("AzureWebJobsStorage connection string is required");
            
            // Read MIN_POOL_SIZE from environment variable, defaulting to 1 if not set or invalid
            if (!int.TryParse(Environment.GetEnvironmentVariable("MIN_POOL_SIZE"), out _minPoolSize) || _minPoolSize < 1)
            {
                _logger.LogWarning("MIN_POOL_SIZE environment variable not found or invalid. Defaulting to 1.");
                _minPoolSize = 1; 
            }
            else 
            {
                _logger.LogInformation($"Minimum VM Pool Size set to: {_minPoolSize}");
            }
           
            _vnetName = Environment.GetEnvironmentVariable("VNET_NAME") ?? "SolidCAM-Golden-Image-vnet";
            _subnetName = Environment.GetEnvironmentVariable("SUBNET_NAME") ?? "default";
            _galleryImageId = Environment.GetEnvironmentVariable("GALLERY_IMAGE_ID") ??
                "/subscriptions/05329ba1-6d97-4b22-808c-9f448c4e9a11/resourceGroups/SolidCAM-Golden-Image_group/providers/Microsoft.Compute/galleries/solidcam_image_gallery/images/SolidCAM-Multisession-Hibernate/versions/0.0.6";
            _guacamoleServerPrivateIp = Environment.GetEnvironmentVariable("GUACAMOLE_SERVER_PRIVATE_IP") ?? ""; // Required
            
            // Set location based on environment variable or default to NorthEurope
            var locationStr = Environment.GetEnvironmentVariable("AZURE_LOCATION")?.ToLowerInvariant();
            _location = AzureLocation.NorthEurope;  // Always use North Europe
            
            // Define location fallback options with westeurope and israelcentral only
            _locationFallbackOptions = new List<AzureLocation>
            {
                AzureLocation.NorthEurope    // Only use North Europe, no fallbacks
            };
                        
            // Remove duplicates and ensure current location is first
            _locationFallbackOptions = _locationFallbackOptions.Distinct().ToList();
            if (_locationFallbackOptions.First() != _location)
            {
                _locationFallbackOptions.Remove(_location);
                _locationFallbackOptions.Insert(0, _location);
            }

            // Read VM_SIZE from environment variable, defaulting to Standard B2as v2 if not set
            var vmSizeString = Environment.GetEnvironmentVariable("VM_SIZE") ?? "Standard_B2as_v2";
            _vmSize = new VirtualMachineSizeType(vmSizeString);

            // Only use the specified VM size without fallbacks
            _vmSizeFallbackOptions = new List<VirtualMachineSizeType>
            {
                _vmSize  // Only use the VM size specified in VM_SIZE environment variable
            };

            _logger.LogInformation($"Using VM size: {_vmSize} from environment variable VM_SIZE='{Environment.GetEnvironmentVariable("VM_SIZE")}'");
            if (string.IsNullOrEmpty(_guacamoleServerPrivateIp))
            {
                _logger.LogError("GUACAMOLE_SERVER_PRIVATE_IP environment variable is not set.");
                throw new InvalidOperationException("GUACAMOLE_SERVER_PRIVATE_IP must be configured.");
            }
            // Initialize Azure Resource Manager client
            var credential = new DefaultAzureCredential(); 
            _armClient = new ArmClient(credential);

            // Get resource group
            var subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID"); 
            SubscriptionResource subscription = string.IsNullOrEmpty(subscriptionId) 
                ? _armClient.GetDefaultSubscription() 
                : _armClient.GetSubscriptionResource(new ResourceIdentifier($"/subscriptions/{subscriptionId}"));

            var resourceGroupName = Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP") ?? "SolidCAM-Golden-Image_group";
            _resourceGroup = subscription.GetResourceGroup(resourceGroupName);

            _logger.LogInformation($"VMPoolManager initialized. Target RG: {_resourceGroup.Id}, Location: {_location}, Pool Size: {_minPoolSize}");
        }

private async Task OptimizeVMForFasterStartupAsync(VirtualMachineResource vm)
{
    _logger.LogInformation($"Running persistent optimization for VM {vm.Data.Name}…");

    // 1) Find the script file (copied to output)
    var scriptPath = Path.Combine(Environment.CurrentDirectory, "optimization.ps1");
    if (!File.Exists(scriptPath))
        throw new FileNotFoundException($"Cannot find {scriptPath}");

    // 2) Read all lines
    var scriptLines = File.ReadAllLines(scriptPath);

    // 3) Build the RunCommand input
    var runCommandInput = new RunCommandInput("RunPowerShellScript");
    foreach (var line in scriptLines)
    {
        runCommandInput.Script.Add(line);
    }

    // 4) Execute it
    try
    {
        var result = await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
        _logger.LogInformation($"Persistent optimization completed for VM {vm.Data.Name}");
        if (result?.Value?.Value != null)
        {
            foreach (var outp in result.Value.Value)
                if (outp.Message?.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
                    _logger.LogWarning($"Optimization warning: {outp.Message}");
        }
    }
    catch (Exception ex)
    {
        _logger.LogWarning(ex, $"Optimization encountered issues for VM {vm.Data.Name}, continuing deallocation.");
    }
}





        /// <summary>
        /// Get current status of the VM pool (VMs named SolidCAM-VM-Pool-*)
        /// </summary>
        public async Task<VMPoolStatus> GetPoolStatusAsync()
        {
            _logger.LogInformation("Getting pool status");
            var result = new VMPoolStatus();

            // Get the VM collection
            var vmCollection = _resourceGroup.GetVirtualMachines();

            // List all VMs potentially belonging to the pool
            await foreach (var vm in vmCollection.GetAllAsync())
            {
                // Filter by naming convention for pool VMs
                if (vm.Data.Name.StartsWith("SolidCAM-VM-Pool-"))
                {
                    try
                    {
                        // Get current VM state using InstanceView
                        var instanceViewResponse = await vm.InstanceViewAsync();
                        var statuses = instanceViewResponse?.Value?.Statuses; 
                        
                        if (statuses != null) {
                             var powerState = statuses.FirstOrDefault(s => s.Code != null && s.Code.StartsWith("PowerState/"))?.Code;

                            if (powerState == "PowerState/deallocated")
                            {
                                result.DeallocatedVMs.Add(vm);
                            }
                            else if (powerState == "PowerState/running")
                            {
                                result.RunningVMs.Add(vm);
                            }
                            // Add this condition to recognize stopped VMs with hibernation too
                            else if (powerState == "PowerState/stopped")
                            {
                                // Check if it has a hibernation state too
                                var hibernateState = statuses?.FirstOrDefault(s => s.Code != null && s.Code.StartsWith("HibernationState/"))?.Code;
                                if (hibernateState == "HibernationState/Hibernated")
                                {
                                    _logger.LogInformation($"VM {vm.Data.Name} is in stopped state with hibernation. Adding to available pool.");
                                    result.DeallocatedVMs.Add(vm);
                                }
                                else
                                {
                                    _logger.LogWarning($"VM {vm.Data.Name} is in stopped state without hibernation. Treating as transitioning.");
                                    result.TransitioningVMs.Add(vm);
                                }
                            }
                        } else {
                            _logger.LogWarning($"Could not retrieve instance view statuses for pool VM {vm.Data.Name}. Treating as transitioning.");
                            result.TransitioningVMs.Add(vm); // If status is unavailable, treat as transitioning
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error getting instance view for pool VM {vm.Data.Name}. Treating as transitioning.");
                        result.TransitioningVMs.Add(vm); // If error getting status, treat as transitioning
                    }
                }
            }

            // Also count and track non-pool VMs to help with quota management
            await foreach (var vm in vmCollection.GetAllAsync())
            {
                if (!vm.Data.Name.StartsWith("SolidCAM-VM-Pool-") && 
                    (vm.Data.Name.StartsWith("SolidCAM-VM-") || vm.Data.Name.StartsWith("SolidCAM-")))
                {
                    result.OtherVMs.Add(vm);
                }
            }

            _logger.LogInformation($"Pool status: {result.DeallocatedVMs.Count} deallocated, {result.RunningVMs.Count} running, " +
                                  $"{result.TransitioningVMs.Count} transitioning, {result.OtherVMs.Count} other SolidCAM VMs");
            return result;
        }

        /// <summary>
        /// Finds and cleans up orphaned NICs and NSGs that don't have an associated VM
        /// </summary>
        public async Task CleanupOrphanedResourcesAsync()
        {
            _logger.LogInformation("Cleaning up orphaned NICs and NSGs...");
            
            // Get all VMs
            var vmCollection = _resourceGroup.GetVirtualMachines();
            var allVms = new List<VirtualMachineResource>();
            await foreach (var vm in vmCollection.GetAllAsync())
            {
                allVms.Add(vm);
            }
            
            // Get all NICs
            var nicCollection = _resourceGroup.GetNetworkInterfaces();
            var orphanedNicIds = new List<string>();
            
            await foreach (var nic in nicCollection.GetAllAsync())
            {
                if (nic.Data.Name.Contains("vm-nic"))
                {
                    // Check if this NIC is attached to any VM
                    bool isAttached = false;
                    foreach (var vm in allVms)
                    {
                        foreach (var nicRef in vm.Data.NetworkProfile.NetworkInterfaces)
                        {
                            if (nicRef.Id == nic.Id)
                            {
                                isAttached = true;
                                break;
                            }
                        }
                        if (isAttached) break;
                    }
                    
                    if (!isAttached)
                    {
                        _logger.LogInformation($"Found orphaned NIC: {nic.Data.Name}");
                        orphanedNicIds.Add(nic.Id);
                        
                        // Try to delete the orphaned NIC
                        try
                        {
                            _logger.LogInformation($"Deleting orphaned NIC: {nic.Data.Name}");
                            await nic.DeleteAsync(Azure.WaitUntil.Completed);
                            _logger.LogInformation($"Successfully deleted orphaned NIC: {nic.Data.Name}");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to delete orphaned NIC {nic.Data.Name}: {ex.Message}");
                        }
                    }
                }
            }
            
            // Get all NSGs
            var nsgCollection = _resourceGroup.GetNetworkSecurityGroups();
            
            await foreach (var nsg in nsgCollection.GetAllAsync())
            {
                if (nsg.Data.Name.Contains("vm-nsg"))
                {
                    // Check if this NSG is attached to any NIC that's not orphaned
                    bool isInUse = false;
                    await foreach (var nic in nicCollection.GetAllAsync())
                    {
                        if (nic.Data.NetworkSecurityGroup != null && nic.Data.NetworkSecurityGroup.Id == nsg.Id)
                        {
                            // Only count if the NIC is not orphaned
                            if (!orphanedNicIds.Contains(nic.Id))
                            {
                                isInUse = true;
                                break;
                            }
                        }
                    }
                    
                    if (!isInUse)
                    {
                        _logger.LogInformation($"Found orphaned NSG: {nsg.Data.Name}");
                        
                        // Try to delete the orphaned NSG
                        try
                        {
                            _logger.LogInformation($"Deleting orphaned NSG: {nsg.Data.Name}");
                            await nsg.DeleteAsync(Azure.WaitUntil.Completed);
                            _logger.LogInformation($"Successfully deleted orphaned NSG: {nsg.Data.Name}");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to delete orphaned NSG {nsg.Data.Name}: {ex.Message}");
                        }
                    }
                }
            }
            
            _logger.LogInformation("Finished cleanup of orphaned resources");
        }

        /// <summary>
        /// Ensures the pool has at least the minimum number of deallocated VMs.
        /// Creates new deallocated VMs if needed.
        /// </summary>
        public async Task EnsurePoolSizeAsync()
        {
            _logger.LogInformation($"Ensuring pool has at least {_minPoolSize} deallocated VMs");

            // First, clean up any orphaned resources
            await CleanupOrphanedResourcesAsync();
            
            var poolStatus = await GetPoolStatusAsync();

            // Calculate how many VMs are currently available or will soon be
            int needed = _minPoolSize - poolStatus.DeallocatedVMs.Count;

            if (needed > 0)
            {
                _logger.LogInformation($"Pool requires {needed} more deallocated VM(s). Creating them in parallel.");

                // Create a list to hold the VM creation tasks
                var creationTasks = new List<Task<VirtualMachineResource>>();
                
                // Start all VM creation tasks in parallel
                for (int i = 0; i < needed; i++)
                {
                    int vmIndex = i; // Capture for logging in the task
                    creationTasks.Add(Task.Run(async () => {
                        try
                        {
                            _logger.LogInformation($"Starting parallel creation of pool VM {vmIndex+1} of {needed}");
                            var vm = await CreatePoolVMAsync();
                            _logger.LogInformation($"Successfully created pool VM {vmIndex+1} of {needed}: {vm.Data.Name}");
                            return vm;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Failed to create pool VM {vmIndex+1} of {needed}");
                            return null;
                        }
                    }));
                }
                
                // Wait for all VM creation tasks to complete
                var results = await Task.WhenAll(creationTasks);
                
                // Count successful creations
                int successCount = results.Count(vm => vm != null);
                _logger.LogInformation($"Successfully created {successCount} out of {needed} requested pool VMs in parallel.");
                
                // Clean up any orphaned resources that might have been created during failures
                await CleanupOrphanedResourcesAsync();
            }
            else
            {
                _logger.LogInformation($"Pool already has sufficient deallocated VMs: {poolStatus.DeallocatedVMs.Count} >= {_minPoolSize}");
            }
        }

         /// <summary>
        /// Creates a new VM (NSG, NIC, VM) with configured password and then deallocates it.
        /// Intended for adding VMs to the pool.
        /// </summary>
        public async Task<VirtualMachineResource> CreatePoolVMAsync()
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            // Using "Pool" in the name to clearly identify these resources
            var vmName = $"SolidCAM-VM-Pool-{timestamp}";
            var nicName = $"vm-nic-pool-{timestamp}";
            var nsgName = $"vm-nsg-pool-{timestamp}";

            _logger.LogInformation($"Creating new pool VM with configured password: {vmName}");

            // For cleanup in case of failure
            NetworkSecurityGroupResource? nsg = null;
            NetworkInterfaceResource? nic = null;

            try
            {
                // Try with different locations if quota is exceeded
                foreach (var locationOption in _locationFallbackOptions)
                {
                    _logger.LogInformation($"Attempting to create VM in location: {locationOption}");
                    
                    // Try with different VM sizes in case of quota issues
                    foreach (var vmSizeOption in _vmSizeFallbackOptions)
                    {
                        try
                        {
                            // Get the virtual network and subnet
                            _logger.LogInformation($"Getting existing VNet: {_vnetName} and subnet: {_subnetName}");
                            VirtualNetworkResource existingVnet = await _resourceGroup.GetVirtualNetworks().GetAsync(_vnetName);
                            SubnetResource subnet = await existingVnet.GetSubnets().GetAsync(_subnetName);

                            // Reuse existing NSG and NIC if they were created in previous attempts
                            if (nsg == null)
                            {
                                // Create NSG
                                _logger.LogInformation($"Creating NSG for pool VM {vmName}: {nsgName}");
                                var nsgData = new NetworkSecurityGroupData()
                                {
                                    Location = locationOption,
                                    SecurityRules =
                                    {
                                        new SecurityRuleData()
                                        {
                                            Name = "AllowRDP_From_Guacamole", Priority = 1000, Access = SecurityRuleAccess.Allow, Direction = SecurityRuleDirection.Inbound,
                                            Protocol = SecurityRuleProtocol.Tcp, SourceAddressPrefix = _guacamoleServerPrivateIp, SourcePortRange = "*",
                                            DestinationAddressPrefix = "*", DestinationPortRange = "3389"
                                        }
                                    }
                                };
                                var nsgCollection = _resourceGroup.GetNetworkSecurityGroups();
                                var nsgCreateOp = await nsgCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, nsgName, nsgData);
                                nsg = nsgCreateOp.Value;
                                _logger.LogInformation($"NSG created: {nsg.Id}");
                            }

                            if (nic == null)
                            {
                                // Create NIC
                                _logger.LogInformation($"Creating network interface {nicName} in subnet {subnet.Id}");
                                var nicData = new NetworkInterfaceData()
                                {
                                    Location = locationOption,
                                    NetworkSecurityGroup = new NetworkSecurityGroupData() { Id = nsg.Id },
                                    IPConfigurations = { new NetworkInterfaceIPConfigurationData() { Name = "ipconfig1", Primary = true, Subnet = new SubnetData() { Id = subnet.Id }, PrivateIPAllocationMethod = NetworkIPAllocationMethod.Dynamic } }
                                };
                                var nicCollection = _resourceGroup.GetNetworkInterfaces();
                                var nicCreateOp = await nicCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, nicName, nicData);
                                nic = nicCreateOp.Value;
                                _logger.LogInformation($"NIC created: {nic.Id}");
                            }

                            // Create VM with current VM size option
                            _logger.LogInformation($"Preparing VM configuration for pool VM {vmName} with size {vmSizeOption} in location {locationOption}...");
                            var imageResourceId = new ResourceIdentifier(_galleryImageId);
                            var vmData = new VirtualMachineData(locationOption) // Use current location option
                            {
                                HardwareProfile = new VirtualMachineHardwareProfile() { VmSize = vmSizeOption }, // Use current size option
                                // Add this line - Note the correct class name
                                AdditionalCapabilities = new Azure.ResourceManager.Compute.Models.AdditionalCapabilities 
                                { 
                                    HibernationEnabled = true 
                                },
                                NetworkProfile = new VirtualMachineNetworkProfile() {
                                    NetworkInterfaces = { new VirtualMachineNetworkInterfaceReference() { Id = nic.Id, Primary = true } }
                                },
                                StorageProfile = new VirtualMachineStorageProfile() {
                                    ImageReference = new ImageReference() { Id = new ResourceIdentifier(_galleryImageId) },
                                    OSDisk = new VirtualMachineOSDisk(DiskCreateOptionType.FromImage) // Ensure OS disk is specified
                                    {
                                        // Optional: Specify disk size, type (e.g., Premium_LRS), caching
                                        Caching = CachingType.ReadWrite, // Common default
                                        ManagedDisk = new VirtualMachineManagedDisk()
                                        {
                                            StorageAccountType = StorageAccountType.StandardLrs  // Or Standard_LRS, StandardSSD_LRS etc. based on image/requirements
                                        }
                                    }
                                },
                                SecurityProfile = new SecurityProfile() { SecurityType = SecurityType.TrustedLaunch }, // Assuming Trusted Launch is desired/compatible
                                OSProfile = new VirtualMachineOSProfile() // Required even with gallery images in this version of the SDK
                                { 
                                    ComputerName = vmName.Length > 15 ? vmName.Substring(0, 15) : vmName, // Windows VM names can't exceed 15 chars
                                    AdminUsername = "localadmin", // Will be overridden by the gallery image, but required by the API
                                    AdminPassword = Program.GenerateSecurePassword(16) // Will be overridden by the gallery image, but required by the API
                                }
                            };
                            _logger.LogInformation($"Creating pool VM: {vmName} using image {_galleryImageId}");
                            var vmCollection = _resourceGroup.GetVirtualMachines();
                            var vmCreateOp = await vmCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, vmName, vmData);
                            VirtualMachineResource vm = vmCreateOp.Value;
                            _logger.LogInformation($"VM creation completed for pool VM: {vm.Data.Name}");

                            // Configure the user accounts while the VM is running (OPTIMIZATION)
                            _logger.LogInformation($"Configuring user accounts for VM {vm.Data.Name} while running...");
                            
                            // Wait for a short time to ensure VM is fully running and services are up
                            _logger.LogInformation($"Allowing brief initialization time for VM {vm.Data.Name}...");
                            await Task.Delay(TimeSpan.FromSeconds(30));
                            
                            // Always use the default password instead of generating a random one
                            string password = "Rt@wqPP7ZvUgtS7"; // Default password
                            bool configSuccess = await Program.ConfigureMultiUserAccountsAsync(vm, password, _logger);
                            
                            if (configSuccess)
                            {
                                _logger.LogInformation($"Successfully configured user accounts with default password for VM {vm.Data.Name}");
                            }
                            else
                            {
                                _logger.LogWarning($"Failed to configure user accounts for VM {vm.Data.Name}. VM will still be added to pool.");
                            }
                            _logger.LogInformation($"Running persistent optimization before hibernating pool VM: {vmName}");
                            await OptimizeVMForFasterStartupAsync(vm);

                            // Now hibernate the VM instead of deallocating
                            _logger.LogInformation($"Hibernating pool VM: {vmName}");
                            await HibernateVMAsync(vm);
                            _logger.LogInformation($"Pool VM hibernated: {vmName} and ready for use");

                            // Update the default VM size and location if a fallback worked
                            if (!vmSizeOption.ToString().Equals(_vmSize.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogInformation($"Setting new default VM size to {vmSizeOption} for future creates");
                                _vmSize = vmSizeOption;
                            }
                            
                            if (!locationOption.Equals(_location))
                            {
                                _logger.LogInformation($"Setting new default location to {locationOption} for future creates");
                                _location = locationOption;
                            }

                            return vm; // Return the hibernated VM resource
                        }
                        catch (RequestFailedException ex) when (ex.Status == 409 && ex.Message.Contains("quota"))
                        {
                            _logger.LogWarning($"Quota limit reached for VM size {vmSizeOption} in location {locationOption}. Error: {ex.Message}");
                            
                            // If this is the last VM size option for this location, continue to the next location
                            if (vmSizeOption.ToString().Equals(_vmSizeFallbackOptions.Last().ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogWarning($"All VM size options exhausted for location {locationOption}. Moving to next location if available.");
                                break; // Break out of VM size loop, continue to next location
                            }
                            
                            // Otherwise continue to try the next size option
                            _logger.LogInformation($"Trying next VM size option...");
                            continue;
                        }
                        catch (RequestFailedException ex) when (ex.Status == 400 && ex.Message.Contains("Hypervisor Generation"))
                        {
                            _logger.LogWarning($"VM size {vmSizeOption} is not compatible with the Hypervisor Generation of the image. Error: {ex.Message}");
                            
                            // If this is the last VM size option for this location, continue to the next location
                            if (vmSizeOption.ToString().Equals(_vmSizeFallbackOptions.Last().ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogWarning($"All VM size options exhausted for location {locationOption}. Moving to next location if available.");
                                break; // Break out of VM size loop, continue to next location
                            }
                            
                            // Otherwise continue to try the next size option
                            _logger.LogInformation($"Trying next VM size option...");
                            continue;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error creating pool VM {vmName} with size {vmSizeOption} in location {locationOption}");
                            
                            // If this is a non-recoverable error, try the next location
                            _logger.LogWarning($"Non-recoverable error for location {locationOption}. Moving to next location if available.");
                            break; // Break out of VM size loop, continue to next location
                        }
                    }
                    // Continue to next location if we get here (all VM sizes exhausted for this location)
                }
                
                // If we've exhausted all locations and VM sizes, clean up and throw
                _logger.LogError("All VM size and location options exhausted due to quota limitations or compatibility issues. Please request a quota increase or check VM size compatibility.");
                await CleanupResources(nsg, nic);
                throw new InvalidOperationException("Failed to create VM with all available size and location options");
            }
            catch (Exception ex)
            {
                // If any exception occurs, clean up the resources
                _logger.LogError(ex, $"Error during VM creation. Cleaning up resources.");
                await CleanupResources(nsg, nic);
                throw;
            }
        }

        /// <summary>
        /// Cleanup NSG and NIC resources in case of VM creation failure
        /// </summary>
        private async Task CleanupResources(NetworkSecurityGroupResource? nsg, NetworkInterfaceResource? nic)
        {
            try
            {
                if (nic != null)
                {
                    _logger.LogInformation($"Cleaning up NIC: {nic.Data.Name}");
                    await nic.DeleteAsync(Azure.WaitUntil.Completed);
                }
                
                if (nsg != null)
                {
                    _logger.LogInformation($"Cleaning up NSG: {nsg.Data.Name}");
                    await nsg.DeleteAsync(Azure.WaitUntil.Completed);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error cleaning up resources: {ex.Message}. Resources may need manual cleanup.");
            }
        }

        /// <summary>
        /// Creates a new VM (NSG, NIC, VM) and returns it in a running state.
        /// Intended for assigning directly to a user when the pool is empty.
        /// </summary>
        public async Task<VirtualMachineResource> CreateAndReturnRunningVMAsync(string purpose = "user")
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            var vmName = $"SolidCAM-VM-{purpose}-{timestamp}";
            var nicName = $"vm-nic-{purpose}-{timestamp}";
            var nsgName = $"vm-nsg-{purpose}-{timestamp}";

            _logger.LogInformation($"Creating new RUNNING VM: {vmName} for purpose: {purpose}");

            // For cleanup in case of failure
            NetworkSecurityGroupResource? nsg = null;
            NetworkInterfaceResource? nic = null;

            try
            {
                // Try with different locations if quota is exceeded
                foreach (var locationOption in _locationFallbackOptions)
                {
                    _logger.LogInformation($"Attempting to create VM in location: {locationOption}");
                    
                    // Try with different VM sizes in case of quota issues
                    foreach (var vmSizeOption in _vmSizeFallbackOptions)
                    {
                        try
                        {
                            // Get the virtual network and subnet
                            _logger.LogInformation($"Getting existing VNet: {_vnetName} and subnet: {_subnetName}");
                            VirtualNetworkResource existingVnet = await _resourceGroup.GetVirtualNetworks().GetAsync(_vnetName);
                            SubnetResource subnet = await existingVnet.GetSubnets().GetAsync(_subnetName);

                            // Reuse existing NSG and NIC if they were created in previous attempts
                            if (nsg == null)
                            {
                                // Create NSG
                                _logger.LogInformation($"Creating NSG for VM {vmName}: {nsgName}");
                                var nsgData = new NetworkSecurityGroupData()
                                {
                                    Location = locationOption,
                                    SecurityRules =
                                    {
                                        new SecurityRuleData()
                                        {
                                            Name = "AllowRDP_From_Guacamole", Priority = 1000, Access = SecurityRuleAccess.Allow, Direction = SecurityRuleDirection.Inbound,
                                            Protocol = SecurityRuleProtocol.Tcp, SourceAddressPrefix = _guacamoleServerPrivateIp, SourcePortRange = "*",
                                            DestinationAddressPrefix = "*", DestinationPortRange = "3389"
                                        }
                                    }
                                };
                                var nsgCollection = _resourceGroup.GetNetworkSecurityGroups();
                                var nsgCreateOp = await nsgCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, nsgName, nsgData);
                                nsg = nsgCreateOp.Value;
                                _logger.LogInformation($"NSG created: {nsg.Id}");
                            }

                            if (nic == null)
                            {
                                // Create NIC
                                _logger.LogInformation($"Creating network interface {nicName} in subnet {subnet.Id}");
                                var nicData = new NetworkInterfaceData()
                                {
                                    Location = locationOption,
                                    NetworkSecurityGroup = new NetworkSecurityGroupData() { Id = nsg.Id },
                                    IPConfigurations = { new NetworkInterfaceIPConfigurationData() { Name = "ipconfig1", Primary = true, Subnet = new SubnetData() { Id = subnet.Id }, PrivateIPAllocationMethod = NetworkIPAllocationMethod.Dynamic } }
                                };
                                var nicCollection = _resourceGroup.GetNetworkInterfaces();
                                var nicCreateOp = await nicCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, nicName, nicData);
                                nic = nicCreateOp.Value;
                                _logger.LogInformation($"NIC created: {nic.Id}");
                            }

                            // Create VM with current VM size option
                            _logger.LogInformation($"Preparing VM configuration for VM: {vmName} with size {vmSizeOption} in location {locationOption}...");
                            var imageResourceId = new ResourceIdentifier(_galleryImageId);
                            var vmData = new VirtualMachineData(locationOption) // Use current location option
                            {
                                HardwareProfile = new VirtualMachineHardwareProfile() { VmSize = vmSizeOption }, // Use current size option
                                // Add this line - Note the correct class name
                                AdditionalCapabilities = new Azure.ResourceManager.Compute.Models.AdditionalCapabilities 
                                { 
                                    HibernationEnabled = true 
                                },
                                NetworkProfile = new VirtualMachineNetworkProfile() {
                                    NetworkInterfaces = { new VirtualMachineNetworkInterfaceReference() { Id = nic.Id, Primary = true } }
                                },
                                StorageProfile = new VirtualMachineStorageProfile() {
                                    ImageReference = new ImageReference() { Id = new ResourceIdentifier(_galleryImageId) },
                                    OSDisk = new VirtualMachineOSDisk(DiskCreateOptionType.FromImage) // Ensure OS disk is specified
                                    {
                                        // Optional: Specify disk size, type (e.g., Premium_LRS), caching
                                        Caching = CachingType.ReadWrite, // Common default
                                        ManagedDisk = new VirtualMachineManagedDisk()
                                        {
                                            StorageAccountType = StorageAccountType.StandardLrs  // Or Standard_LRS, StandardSSD_LRS etc. based on image/requirements
                                        }
                                    }
                                },
                                SecurityProfile = new SecurityProfile() { SecurityType = SecurityType.TrustedLaunch }, // Assuming Trusted Launch is desired/compatible
                                OSProfile = new VirtualMachineOSProfile() // Required even with gallery images in this version of the SDK
                                { 
                                    ComputerName = vmName.Length > 15 ? vmName.Substring(0, 15) : vmName, // Windows VM names can't exceed 15 chars
                                    AdminUsername = "localadmin", // Will be overridden by the gallery image, but required by the API
                                    AdminPassword = Program.GenerateSecurePassword(16) // Will be overridden by the gallery image, but required by the API
                                }
                            };
                            _logger.LogInformation($"Creating VM: {vmName} using image {_galleryImageId}");
                            var vmCollection = _resourceGroup.GetVirtualMachines();
                            // CreateOrUpdate leaves the VM in a running state by default
                            var vmCreateOp = await vmCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, vmName, vmData);
                            VirtualMachineResource vm = vmCreateOp.Value;
                            _logger.LogInformation($"VM creation completed for: {vm.Data.Name}. VM is RUNNING.");

                            // Update the default VM size and location if a fallback worked
                            if (!vmSizeOption.ToString().Equals(_vmSize.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogInformation($"Setting new default VM size to {vmSizeOption} for future creates");
                                _vmSize = vmSizeOption;
                            }
                            
                            if (!locationOption.Equals(_location))
                            {
                                _logger.LogInformation($"Setting new default location to {locationOption} for future creates");
                                _location = locationOption;
                            }

                            return vm; // Return the running VM
                        }
                        catch (RequestFailedException ex) when (ex.Status == 409 && ex.Message.Contains("quota"))
                        {
                            _logger.LogWarning($"Quota limit reached for VM size {vmSizeOption} in location {locationOption}. Error: {ex.Message}");
                            
                            // If this is the last VM size option for this location, continue to the next location
                            if (vmSizeOption.ToString().Equals(_vmSizeFallbackOptions.Last().ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogWarning($"All VM size options exhausted for location {locationOption}. Moving to next location if available.");
                                break; // Break out of VM size loop, continue to next location
                            }
                            
                            // Otherwise continue to try the next size option
                            _logger.LogInformation($"Trying next VM size option...");
                            continue;
                        }
                        catch (RequestFailedException ex) when (ex.Status == 400 && ex.Message.Contains("Hypervisor Generation"))
                        {
                            _logger.LogWarning($"VM size {vmSizeOption} is not compatible with the Hypervisor Generation of the image. Error: {ex.Message}");
                            
                            // If this is the last VM size option for this location, continue to the next location
                            if (vmSizeOption.ToString().Equals(_vmSizeFallbackOptions.Last().ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogWarning($"All VM size options exhausted for location {locationOption}. Moving to next location if available.");
                                break; // Break out of VM size loop, continue to next location
                            }
                            
                            // Otherwise continue to try the next size option
                            _logger.LogInformation($"Trying next VM size option...");
                            continue;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error creating running VM ({purpose}): {vmName} with size {vmSizeOption} in location {locationOption}");
                            
                            // If this is a non-recoverable error, try the next location
                            _logger.LogWarning($"Non-recoverable error for location {locationOption}. Moving to next location if available.");
                            break; // Break out of VM size loop, continue to next location
                        }
                    }
                    // Continue to next location if we get here (all VM sizes exhausted for this location)
                }
                
                // If we've exhausted all locations and VM sizes, clean up and throw
                _logger.LogError("All VM size and location options exhausted due to quota limitations or compatibility issues. Please request a quota increase or check VM size compatibility.");
                await CleanupResources(nsg, nic);
                throw new InvalidOperationException("Failed to create VM with all available location and size options");
            }
            catch (Exception ex)
            {
                // If any exception occurs, clean up the resources
                _logger.LogError(ex, $"Error during VM creation. Cleaning up resources.");
                await CleanupResources(nsg, nic);
                throw;
            }
        }

        /// <summary>
        /// Allocates a VM for a user. If the pool has deallocated VMs, starts one and returns it.
        /// If the pool is empty, throws an exception.
        /// </summary>
        public async Task<VirtualMachineResource> AllocateVMFromPoolAsync()
        {
            _logger.LogInformation("Allocating VM from pool");
            
            // Get current pool status
            var poolStatus = await GetPoolStatusAsync();

            // Check if there are any VMs available in the pool
            if (poolStatus.DeallocatedVMs.Count > 0)
            {
                // Select a VM from the pool
                var vmToStart = poolStatus.DeallocatedVMs[0];
                _logger.LogInformation($"Selected VM from pool: {vmToStart.Data.Name}");
                
                // Start the VM with WaitUntil.Started instead of WaitUntil.Completed
                // This returns control faster while the VM continues starting in the background
                _logger.LogInformation($"Starting VM from pool: {vmToStart.Data.Name} (background operation)");
                await vmToStart.PowerOnAsync(WaitUntil.Started);
                
                return vmToStart;
            }
            else
            {
                _logger.LogError("No VMs available in the pool. Automatic VM creation is DISABLED.");
                throw new InvalidOperationException("No VMs available in the pool. New VMs will NOT be created automatically.");
            }
        }
        /// Hibernates a VM instead of deallocating it
        /// </summary>
        private async Task HibernateVMAsync(VirtualMachineResource vm)
        {
            try
            {
                _logger.LogInformation($"Hibernating VM {vm.Data.Name}...");
                
                // Use deallocate with hibernate=true instead of PowerOff
                await vm.DeallocateAsync(WaitUntil.Completed, hibernate: true);
                _logger.LogInformation($"Successfully hibernated VM {vm.Data.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to hibernate VM {vm.Data.Name}. Attempting normal deallocate instead.");
                // Fallback to normal deallocation if hibernation fails
                await vm.DeallocateAsync(WaitUntil.Completed);
                _logger.LogInformation($"VM {vm.Data.Name} deallocated as fallback");
            }
        }
    }

    
    

    /// <summary>
    /// Represents the status of the VM pool.
    /// </summary>
    public class VMPoolStatus
    {
        public List<VirtualMachineResource> DeallocatedVMs { get; set; } = new List<VirtualMachineResource>();
        public List<VirtualMachineResource> RunningVMs { get; set; } = new List<VirtualMachineResource>();
        public List<VirtualMachineResource> TransitioningVMs { get; set; } = new List<VirtualMachineResource>();
        public List<VirtualMachineResource> OtherVMs { get; set; } = new List<VirtualMachineResource>();
        
        public int TotalVMCount => DeallocatedVMs.Count + RunningVMs.Count + TransitioningVMs.Count + OtherVMs.Count;
    }
}