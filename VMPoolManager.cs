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
                "/subscriptions/05329ba1-6d97-4b22-808c-9f448c4e9a11/resourceGroups/SolidCAM-Golden-Image_group/providers/Microsoft.Compute/galleries/solidcam_image_gallery/images/solidcam-golden-image/versions/1.0.2";
            _guacamoleServerPrivateIp = Environment.GetEnvironmentVariable("GUACAMOLE_SERVER_PRIVATE_IP") ?? ""; // Required
            
            // Set location based on environment variable or default to NorthEurope
            var locationStr = Environment.GetEnvironmentVariable("AZURE_LOCATION")?.ToLowerInvariant();
            _location = locationStr switch
            {
                "westeurope" => AzureLocation.WestEurope,
                "eastus" => AzureLocation.EastUS,
                "eastus2" => AzureLocation.EastUS2,
                "westus" => AzureLocation.WestUS,
                "westus2" => AzureLocation.WestUS2,
                "southcentralus" => AzureLocation.SouthCentralUS,
                "northcentralus" => AzureLocation.NorthCentralUS,
                "centralus" => AzureLocation.CentralUS,
                "francecentral" => AzureLocation.FranceCentral,
                "uksouth" => AzureLocation.UKSouth,
                "ukwest" => AzureLocation.UKWest,
                "eastasia" => AzureLocation.EastAsia,
                "southeastasia" => AzureLocation.SoutheastAsia,
                "japaneast" => AzureLocation.JapanEast,
                "japanwest" => AzureLocation.JapanWest,
                "australiaeast" => AzureLocation.AustraliaEast,
                "australiasoutheast" => AzureLocation.AustraliaSoutheast,
                "southindia" => AzureLocation.SouthIndia,
                "centralindia" => AzureLocation.CentralIndia,
                "westindia" => AzureLocation.WestIndia,
                "canadacentral" => AzureLocation.CanadaCentral,
                "canadaeast" => AzureLocation.CanadaEast,
                "germanywestcentral" => AzureLocation.GermanyWestCentral,
                _ => AzureLocation.NorthEurope,
            };
            
            // Define location fallback options with good distance between regions to avoid regional outages
            _locationFallbackOptions = new List<AzureLocation>
            {
                _location,                  // Primary location first
                AzureLocation.WestEurope,   // West Europe
                AzureLocation.UKSouth,      // UK South
                AzureLocation.FranceCentral, // France Central
                AzureLocation.GermanyWestCentral, // Germany West Central
                AzureLocation.NorthEurope   // North Europe (if not already primary)
            };
            
            // Remove duplicates and ensure current location is first
            _locationFallbackOptions = _locationFallbackOptions.Distinct().ToList();
            if (_locationFallbackOptions.First() != _location)
            {
                _locationFallbackOptions.Remove(_location);
                _locationFallbackOptions.Insert(0, _location);
            }

            // Read VM_SIZE from environment variable, defaulting to Standard_D2s_v3 if not set
            var vmSizeString = Environment.GetEnvironmentVariable("VM_SIZE") ?? "Standard_D2s_v3";
            _vmSize = new VirtualMachineSizeType(vmSizeString);

            // Define fallback VM sizes that are compatible with Generation 2 Hypervisor
            // UPDATED: Only include verified 1-CPU options that are Generation 2 compatible
            _vmSizeFallbackOptions = new List<VirtualMachineSizeType>
            {
                new VirtualMachineSizeType("Standard_B1ls"),    // 1 vCPU, Gen2 compatible
                new VirtualMachineSizeType("Standard_B1s"),     // 1 vCPU, Gen2 compatible
                new VirtualMachineSizeType("Standard_B1ms"),    // 1 vCPU, Gen2 compatible
                new VirtualMachineSizeType("Standard_DS1_v2"),  // 1 vCPU, Gen2 compatible
                new VirtualMachineSizeType("Standard_D2s_v3"),  // 2 vCPUs, Gen2 compatible
                new VirtualMachineSizeType("Standard_D4s_v3"),  // 4 vCPUs, Gen2 compatible
                new VirtualMachineSizeType("Standard_D2s_v4"),  // 2 vCPUs, Gen2 compatible
                new VirtualMachineSizeType("Standard_D4s_v4"),  // 4 vCPUs, Gen2 compatible
                new VirtualMachineSizeType("Standard_D2s_v5"),  // 2 vCPUs, Gen2 compatible
                new VirtualMachineSizeType("Standard_D2as_v4")  // 2 vCPUs, AMD-based, Gen2 compatible
            };

            // Ensure the user-configured VM size is tried first if it's not in the list
            bool hasConfiguredSize = _vmSizeFallbackOptions.Any(s => s.ToString() == _vmSize.ToString());
            if (!hasConfiguredSize)
            {
                _vmSizeFallbackOptions.Insert(0, _vmSize);
            }
            else
            {
                // If it's in the list, move it to the front
                _vmSizeFallbackOptions.RemoveAll(s => s.ToString() == _vmSize.ToString());
                _vmSizeFallbackOptions.Insert(0, _vmSize);
            }

            _logger.LogInformation($"Configured VM size: {_vmSize}, with {_vmSizeFallbackOptions.Count} fallback options");

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
                            // Treat starting/stopping/deallocating as transitioning
                            else if (powerState == "PowerState/starting" || powerState == "PowerState/stopping" || powerState == "PowerState/deallocating")
                            {
                                result.TransitioningVMs.Add(vm);
                            }
                            else {
                                _logger.LogWarning($"Pool VM {vm.Data.Name} found with unknown or unexpected power state: {powerState ?? "null"}. Treating as transitioning.");
                                result.TransitioningVMs.Add(vm); // Add to transitioning if state is unclear
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
                _logger.LogInformation($"Pool requires {needed} more deallocated VM(s). Creating them now.");

                // Create VMs one at a time (sequentially) to better handle and report errors
                for (int i = 0; i < needed; i++)
                {
                    try
                    {
                        _logger.LogInformation($"Creating pool VM {i+1} of {needed}");
                        await CreatePoolVMAsync();
                        _logger.LogInformation($"Successfully created pool VM {i+1} of {needed}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Failed to create pool VM {i+1} of {needed}");
                        // Continue with next VM even if this one failed
                    }
                }
                
                // Re-check the pool status to see how many were actually created
                var updatedStatus = await GetPoolStatusAsync();
                int actuallyCreated = updatedStatus.DeallocatedVMs.Count - poolStatus.DeallocatedVMs.Count;
                _logger.LogInformation($"Successfully created {actuallyCreated} out of {needed} requested pool VMs.");
                
                // Clean up any orphaned resources that might have been created during failures
                await CleanupOrphanedResourcesAsync();
            }
            else
            {
                _logger.LogInformation($"Pool already has sufficient deallocated VMs: {poolStatus.DeallocatedVMs.Count} >= {_minPoolSize}");
            }
        }

        /// <summary>
        /// Creates a new VM (NSG, NIC, VM) and immediately deallocates it.
        /// Intended for adding VMs to the pool.
        /// </summary>
        public async Task<VirtualMachineResource> CreatePoolVMAsync()
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            // Using "Pool" in the name to clearly identify these resources
            var vmName = $"SolidCAM-VM-Pool-{timestamp}";
            var nicName = $"vm-nic-pool-{timestamp}";
            var nsgName = $"vm-nsg-pool-{timestamp}";

            _logger.LogInformation($"Creating new DEALLOCATED pool VM: {vmName}");

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
                            var vmData = new VirtualMachineData(locationOption)
                            {
                                HardwareProfile = new VirtualMachineHardwareProfile() { VmSize = vmSizeOption },
                                NetworkProfile = new VirtualMachineNetworkProfile() { NetworkInterfaces = { new VirtualMachineNetworkInterfaceReference() { Id = nic.Id, Primary = true } } },
                                StorageProfile = new VirtualMachineStorageProfile() { ImageReference = new ImageReference() { Id = imageResourceId } },
                                SecurityProfile = new SecurityProfile() { SecurityType = SecurityType.TrustedLaunch }
                            };
                            _logger.LogInformation($"Creating pool VM: {vmName} using image {_galleryImageId}");
                            var vmCollection = _resourceGroup.GetVirtualMachines();
                            var vmCreateOp = await vmCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, vmName, vmData);
                            VirtualMachineResource vm = vmCreateOp.Value;
                            _logger.LogInformation($"VM creation completed for pool VM: {vm.Data.Name}");

                            // Immediately deallocate the VM to save costs and add it to the pool correctly
                            _logger.LogInformation($"Deallocating pool VM: {vmName}");
                            await vm.DeallocateAsync(Azure.WaitUntil.Completed);
                            _logger.LogInformation($"Pool VM deallocated: {vmName}");

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

                            return vm; // Return the deallocated VM resource
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
                            var vmData = new VirtualMachineData(locationOption)
                            {
                                HardwareProfile = new VirtualMachineHardwareProfile() { VmSize = vmSizeOption },
                                NetworkProfile = new VirtualMachineNetworkProfile() { NetworkInterfaces = { new VirtualMachineNetworkInterfaceReference() { Id = nic.Id, Primary = true } } },
                                StorageProfile = new VirtualMachineStorageProfile() { ImageReference = new ImageReference() { Id = imageResourceId } },
                                SecurityProfile = new SecurityProfile() { SecurityType = SecurityType.TrustedLaunch }
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
        /// Allocates a VM for a user. If the pool has deallocated VMs, starts one and triggers pool replenishment.
        /// If the pool is empty, creates a new running VM for the user and triggers creation of a deallocated VM for the pool.
        /// </summary>
        public async Task<VirtualMachineResource> AllocateVMFromPoolAsync()
        {
            _logger.LogInformation("Allocating VM from pool");

            try
            {
                var poolStatus = await GetPoolStatusAsync();

                VirtualMachineResource vmToReturn; // Declare VM to return

                if (poolStatus.DeallocatedVMs.Count == 0)
                {
                    // SCENARIO 1: POOL EMPTY
                    _logger.LogWarning("No deallocated VMs available in pool. Creating a new RUNNING VM for user.");

                    // 1. Create the running VM for the user
                    vmToReturn = await CreateAndReturnRunningVMAsync("user");
                    _logger.LogInformation($"Created running VM for user: {vmToReturn.Data.Name}");

                    // 2. Start a SINGLE background task to maintain the pool
                    _logger.LogInformation($"Starting background task to maintain pool at minimum size ({_minPoolSize}).");
                    _ = Task.Run(async () => {
                        try
                        {
                            // This will create exactly the number of VMs needed to reach MIN_POOL_SIZE
                            await EnsurePoolSizeAsync();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error in background pool maintenance task.");
                        }
                    });
                }
                else
                {
                    // SCENARIO 2: POOL NOT EMPTY
                    _logger.LogInformation($"Found {poolStatus.DeallocatedVMs.Count} deallocated VM(s) in pool. Starting one.");
                    // Take the first deallocated VM
                    var vmToStart = poolStatus.DeallocatedVMs[0];
                    _logger.LogInformation($"Starting VM from pool: {vmToStart.Data.Name}");
                    
                    // Start the VM and wait for the operation to complete
                    await vmToStart.PowerOnAsync(Azure.WaitUntil.Completed);
                    _logger.LogInformation($"VM {vmToStart.Data.Name} started successfully.");
                    vmToReturn = vmToStart; // Assign the started VM to return

                    // UPDATED: Don't replenish immediately, just log status
                    // Log the remaining pool size but don't replenish immediately
                    _logger.LogInformation($"Pool now has {poolStatus.DeallocatedVMs.Count - 1} deallocated VMs remaining.");
                    
                    // Only log if pool is below minimum (next scheduled maintenance will handle replenishment)
                    if ((poolStatus.DeallocatedVMs.Count - 1) < _minPoolSize)
                    {
                        _logger.LogInformation($"Remaining pool size {poolStatus.DeallocatedVMs.Count - 1} is below minimum {_minPoolSize}. Will be replenished during next scheduled maintenance.");
                    }
                }

                // Return the VM assigned to the user (either newly created or started from pool)
                _logger.LogInformation($"Returning VM {vmToReturn.Data.Name} for user assignment.");
                return vmToReturn;
            }
            catch (Exception ex)
            {
                // Log the exception details
                _logger.LogError(ex, "Unhandled error during VM allocation process.");
                throw; // Rethrow the exception so the calling function knows something went wrong
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