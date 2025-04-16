using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Resources;
using Azure.Core;
using Azure;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Net;

namespace DeployVMFunction
{
    public class StopVMRequest
    {
        public string? vmName { get; set; }
        public string? resourceGroup { get; set; }
        public string? username { get; set; }  // Username to release (e.g., SolidCAMOperator2)
    }

    public static class StopVM
    {
        [Function("StopVM")]
        public static async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req)
        {
            var log = req.FunctionContext.GetLogger("StopVM");
            log.LogInformation("Processing request to stop and delete VM resources (ISOLATED WORKER).");

            // Add CORS handling
            // Check if it's a CORS preflight request
            if (req.Method.Equals("OPTIONS"))
            {
                var response = req.CreateResponse(HttpStatusCode.OK);
                response.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                response.Headers.Add("Access-Control-Allow-Methods", "POST, OPTIONS");
                response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization");
                response.Headers.Add("Access-Control-Allow-Credentials", "true");
                return response;
            }

            string? vmName = null;
            string? resourceGroupName = null;

            try
            {
                var data = await req.ReadFromJsonAsync<StopVMRequest>();
                vmName = data?.vmName;
                resourceGroupName = data?.resourceGroup;
            }
            catch (JsonException jsonEx)
            {
                log.LogError($"Error deserializing request body: {jsonEx.Message}");
                var badRequestJson = req.CreateResponse(HttpStatusCode.BadRequest);
                // Add CORS headers
                badRequestJson.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                badRequestJson.Headers.Add("Access-Control-Allow-Credentials", "true");
                await badRequestJson.WriteStringAsync("Invalid JSON format in request body.");
                return badRequestJson;
            }
            catch (Exception ex)
            {
                log.LogError($"Error reading request body: {ex.Message}");
                var badRequestRead = req.CreateResponse(HttpStatusCode.BadRequest);
                // Add CORS headers
                badRequestRead.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                badRequestRead.Headers.Add("Access-Control-Allow-Credentials", "true");
                await badRequestRead.WriteStringAsync("Could not read request body.");
                return badRequestRead;
            }

            if (string.IsNullOrEmpty(vmName) || string.IsNullOrEmpty(resourceGroupName))
            {
                log.LogError("VM name or resource group missing from request body.");
                var badRequestParams = req.CreateResponse(HttpStatusCode.BadRequest);
                // Add CORS headers
                badRequestParams.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                badRequestParams.Headers.Add("Access-Control-Allow-Credentials", "true");
                await badRequestParams.WriteStringAsync("Please pass vmName and resourceGroup in the JSON request body.");
                return badRequestParams;
            }

            try
            {
                var credential = new DefaultAzureCredential();
                var armClient = new ArmClient(credential);

                var subscription = await armClient.GetDefaultSubscriptionAsync();
                log.LogInformation($"Subscription ID: {subscription.Data.SubscriptionId}");
                ResourceGroupResource resourceGroupResource = await subscription.GetResourceGroupAsync(resourceGroupName);

                log.LogInformation($"Attempting to get VM: {vmName} in RG: {resourceGroupName}");
                VirtualMachineCollection vmCollection = resourceGroupResource.GetVirtualMachines();

                bool vmExists = await vmCollection.ExistsAsync(vmName);
                if (!vmExists)
                {
                    log.LogWarning($"VM {vmName} not found in resource group {resourceGroupName}.");
                    var notFoundResponse = req.CreateResponse(HttpStatusCode.NotFound);
                    // Add CORS headers
                    notFoundResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                    notFoundResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await notFoundResponse.WriteStringAsync($"VM {vmName} not found.");
                    return notFoundResponse;
                }

                VirtualMachineResource vm = await vmCollection.GetAsync(vmName);
                
                // If username was provided, we'll just release that account and not delete the VM
                // Get username from the request data
                string? username = null;
                try {
                    var reqData = await req.ReadFromJsonAsync<StopVMRequest>();
                    username = reqData?.username;
                } catch {
                    // If we can't read the username, we'll just proceed with the VM deletion
                    log.LogWarning("Could not read username from request, will proceed with VM deletion");
                }
                if (!string.IsNullOrEmpty(username) && username.StartsWith("SolidCAMOperator"))
                {
                    log.LogInformation($"Username {username} provided - will just release this account instead of deleting VM");
                    
                    // Try to parse the account number
                    if (int.TryParse(username.Replace("SolidCAMOperator", ""), out int accountNumber) &&
                        accountNumber >= 1 && accountNumber <= 3)
                    {
                        try
                        {
                            // Initialize VM assignment tracker
                            var storageConnectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
                            if (!string.IsNullOrEmpty(storageConnectionString))
                            {
                                log.LogInformation($"Releasing account {username} (account #{accountNumber}) on VM {vmName}");
                                var assignmentTracker = new VMAssignmentTracker(log, storageConnectionString);
                                await assignmentTracker.ReleaseAccountOnVMAsync(vmName, accountNumber);
                                
                                var releaseResponse = req.CreateResponse(HttpStatusCode.OK);
                                releaseResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                                releaseResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                                await releaseResponse.WriteAsJsonAsync(new {
                                    status = "success",
                                    message = $"User account {username} released on VM {vmName}"
                                });
                                return releaseResponse;
                            }
                        }
                        catch (Exception ex)
                        {
                            log.LogError(ex, $"Error releasing user account {username} on VM {vmName}");
                            // Continue with VM deletion as fallback
                        }
                    }
                }
                
                // If we get here, we're deleting the entire VM (either no username or failed to release)
                // Store network interface IDs before deleting the VM
                var networkInterfaceIds = vm.Data.NetworkProfile.NetworkInterfaces.Select(ni => ni.Id).ToList();

                // Release all VM accounts in the tracker if available
                try
                {
                    var storageConnectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
                    if (!string.IsNullOrEmpty(storageConnectionString))
                    {
                        log.LogInformation($"Marking VM {vmName} as deleted in assignment tracker");
                        var assignmentTracker = new VMAssignmentTracker(log, storageConnectionString);
                        await assignmentTracker.MarkVMAsDeletedAsync(vmName);
                    }
                }
                catch (Exception ex)
                {
                    log.LogWarning(ex, $"Failed to mark VM {vmName} as deleted in assignment tracker. Continuing with deletion.");
                }
                // Network interface IDs already stored above

                // Delete the VM (instead of just deallocating it)
                log.LogInformation($"Deleting VM: {vmName}");
                await vm.DeleteAsync(Azure.WaitUntil.Completed);
                log.LogInformation($"VM {vmName} deleted successfully.");

                // Delete associated network interfaces
                foreach (var nicId in networkInterfaceIds)
                {
                    try 
                    {
                        log.LogInformation($"Deleting network interface: {nicId}");
                        var nicResource = armClient.GetNetworkInterfaceResource(nicId);
                        
                        // Store NSG ID before deleting the NIC
                        string? nsgId = null;
                        try
                        {
                            var nicResponse = await nicResource.GetAsync();
                            var nic = nicResponse.Value;
                            nsgId = nic.Data.NetworkSecurityGroup?.Id;
                        }
                        catch (Exception ex)
                        {
                            log.LogWarning($"Could not retrieve NSG for NIC {nicId}: {ex.Message}");
                        }
                        
                        // Delete the NIC
                        await nicResource.DeleteAsync(Azure.WaitUntil.Completed);
                        log.LogInformation($"Network interface {nicId} deleted successfully.");
                        
                        // Delete associated NSG if it exists
                        if (!string.IsNullOrEmpty(nsgId))
                        {
                            try
                            {
                                log.LogInformation($"Deleting network security group: {nsgId}");
                                var nsgResource = armClient.GetNetworkSecurityGroupResource(new ResourceIdentifier(nsgId));
                                await nsgResource.DeleteAsync(Azure.WaitUntil.Completed);
                                log.LogInformation($"Network security group {nsgId} deleted successfully.");
                            }
                            catch (Exception ex)
                            {
                                log.LogWarning($"Error deleting NSG {nsgId}: {ex.Message}");
                                // Continue with cleanup even if NSG deletion fails
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        log.LogWarning($"Error deleting network interface {nicId}: {ex.Message}");
                        // Continue with cleanup even if NIC deletion fails
                    }
                }

                var responseOk = req.CreateResponse(HttpStatusCode.OK);
                // Add CORS headers
                responseOk.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                responseOk.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseOk.WriteAsJsonAsync(new {
                    status = "success",
                    message = $"VM {vmName} and associated resources deleted successfully"
                });
                return responseOk;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                log.LogError($"VM {vmName} not found during operation. Error: {ex.Message}");
                var notFoundResponse = req.CreateResponse(HttpStatusCode.NotFound);
                // Add CORS headers
                notFoundResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                notFoundResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                await notFoundResponse.WriteStringAsync($"VM {vmName} not found.");
                return notFoundResponse;
            }
            catch (Exception ex)
            {
                log.LogError($"Error stopping VM {vmName}: {ex.ToString()}");
                var responseCatch = req.CreateResponse(HttpStatusCode.InternalServerError);
                // Add CORS headers
                responseCatch.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                responseCatch.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseCatch.WriteAsJsonAsync(new { error = $"An unexpected error occurred: {ex.Message ?? "Unknown error"}" });
                return responseCatch;
            }
        }
    }
}