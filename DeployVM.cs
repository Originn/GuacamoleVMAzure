using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // Keep for potential future JSON handling if needed
using Newtonsoft.Json.Linq; // Keep for Guacamole JObject manipulation
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models; // Needed for VirtualMachineRunCommandResult, RunCommandInput, InstanceViewStatus etc.
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models; // Needed for Network related models
using Azure.ResourceManager.Resources; // Needed for SubscriptionResource, ResourceGroupResource
using Azure.Core;
using Azure; // Needed for ArmOperation, Response, WaitUntil etc.
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Net;
using System.Net.Sockets; // Used for TcpClient in RDP check

namespace DeployVMFunction
{
    public static class DeployVM
    {
        // Define a static HttpClient to reuse connections with SSL certificate validation
        private static readonly HttpClient httpClient;

        // Static constructor to initialize HttpClient with certificate validation handling
        static DeployVM()
        {
            var handler = new HttpClientHandler
            {
                // WARNING: Accepting all certificates is insecure. Use only for trusted environments or replace with proper validation.
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
            httpClient = new HttpClient(handler);
        }

        [Function("DeployVM")]
        public static async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req)
        {
            var log = req.FunctionContext.GetLogger("DeployVM");
            log.LogInformation("C# HTTP trigger function processed a request for VM deployment from pool (ISOLATED WORKER).");

            string allowedOrigin = Environment.GetEnvironmentVariable("AllowedCorsOrigin") ?? "https://solidcamportal743899.z16.web.core.windows.net";

            if (req.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                log.LogInformation("Handling CORS preflight request.");
                var optionsResponse = req.CreateResponse(HttpStatusCode.OK);
                optionsResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                optionsResponse.Headers.Add("Access-Control-Allow-Methods", "POST, OPTIONS");
                optionsResponse.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization");
                optionsResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                return optionsResponse;
            }

            try
            {
                // --- Configuration from Environment Variables ---
                string? guacamoleServerPrivateIp = Environment.GetEnvironmentVariable("GUACAMOLE_SERVER_PRIVATE_IP");
                string? guacamoleApiBaseUrl = Environment.GetEnvironmentVariable("GUACAMOLE_API_BASE_URL");
                string? guacamoleApiUsername = Environment.GetEnvironmentVariable("GUACAMOLE_API_USERNAME");
                string? guacamoleApiPassword = Environment.GetEnvironmentVariable("GUACAMOLE_API_PASSWORD");

                var missingVars = new List<string>();
                if (string.IsNullOrEmpty(guacamoleServerPrivateIp)) missingVars.Add("GUACAMOLE_SERVER_PRIVATE_IP");
                if (string.IsNullOrEmpty(guacamoleApiBaseUrl)) missingVars.Add("GUACAMOLE_API_BASE_URL");
                if (string.IsNullOrEmpty(guacamoleApiUsername)) missingVars.Add("GUACAMOLE_API_USERNAME");
                if (string.IsNullOrEmpty(guacamoleApiPassword)) missingVars.Add("GUACAMOLE_API_PASSWORD");

                if (missingVars.Any())
                {
                    log.LogError($"Missing required environment variables: {string.Join(", ", missingVars)}");
                    var configErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    configErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    configErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await configErrorResponse.WriteStringAsync("Server configuration error: Missing required environment variables.");
                    return configErrorResponse;
                }
                log.LogInformation($"Using Guacamole Server Private IP: {guacamoleServerPrivateIp}");
                log.LogInformation($"Using Guacamole API Base URL: {guacamoleApiBaseUrl}");

                var poolManager = new VMPoolManager(log);

                // Instead of generating a password immediately, we'll check storage first
                string? randomPassword = null;

                log.LogInformation("Requesting VM from the warm pool");
                Task<VirtualMachineResource> vmAllocationTask;
                try
                {
                    vmAllocationTask = poolManager.AllocateVMFromPoolAsync();
                }
                catch (RequestFailedException ex) when (ex.Status == 409 && ex.Message.Contains("quota", StringComparison.OrdinalIgnoreCase))
                {
                    log.LogError(ex, $"Azure quota limit reached. Unable to allocate VM.");
                    var quotaErrorResponse = req.CreateResponse(HttpStatusCode.ServiceUnavailable);
                    quotaErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    quotaErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await quotaErrorResponse.WriteAsJsonAsync(new { error = "Azure subscription quota limit reached.", details = ex.Message });
                    return quotaErrorResponse;
                }
                catch (InvalidOperationException ex) when (ex.Message.Contains("Failed to create VM", StringComparison.OrdinalIgnoreCase))
                {
                     log.LogError(ex, $"Failed to create VM after exhausting options.");
                     var creationErrorResponse = req.CreateResponse(HttpStatusCode.ServiceUnavailable);
                     creationErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                     creationErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await creationErrorResponse.WriteAsJsonAsync(new { error = "Failed to provision a virtual machine.", details = ex.Message });
                    return creationErrorResponse;
                }
                VirtualMachineResource vm = await vmAllocationTask;
                string vmName = vm.Data?.Name ?? "UnknownVM";
                log.LogInformation($"Allocated VM {vmName} from pool");

                string? targetVmPrivateIp = null;
                NetworkInterfaceResource? primaryNic = null;
                try
                {
                    var firstNetworkInterfaceRef = vm.Data?.NetworkProfile?.NetworkInterfaces?.FirstOrDefault();
                    if (firstNetworkInterfaceRef?.Id != null)
                    {
                        var nicId = firstNetworkInterfaceRef.Id;
                        var armClient = new ArmClient(new DefaultAzureCredential());
                        primaryNic = armClient.GetNetworkInterfaceResource(nicId);
                        log.LogInformation($"Fetching NIC details for {nicId}...");
                        Response<NetworkInterfaceResource> refreshedNicResponse = await primaryNic.GetAsync();
                        NetworkInterfaceData? refreshedNicData = refreshedNicResponse.Value?.Data;
                        var ipConfig = refreshedNicData?.IPConfigurations?.FirstOrDefault(ipc => ipc.Primary ?? false) ?? refreshedNicData?.IPConfigurations?.FirstOrDefault();
                        targetVmPrivateIp = ipConfig?.PrivateIPAddress;
                    } else { log.LogWarning($"VM {vmName} has no network interfaces defined."); }
                } catch (Exception ipEx) { log.LogError(ipEx, $"Error retrieving NIC or private IP address for VM {vmName}"); }

                if (string.IsNullOrEmpty(targetVmPrivateIp))
                {
                    log.LogError($"Could not retrieve primary private IP address for VM {vmName}. Deployment cannot proceed.");
                    var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    errorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    errorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await errorResponse.WriteStringAsync("Could not retrieve VM private IP address.");
                    return errorResponse;
                }
                log.LogInformation($"VM Private IP for {vmName}: {targetVmPrivateIp}");

                log.LogInformation($"VM {vmName} has been allocated from the pool. Resuming from hibernation...");
                
                // Check if VM is in hibernated state and resume it
                bool isHibernated = false;
                try {
                    var instanceView = await vm.InstanceViewAsync();
                    var statuses = instanceView?.Value?.Statuses;
                    if (statuses != null) {
                        var powerState = statuses.FirstOrDefault(s => s.Code != null && s.Code.StartsWith("PowerState/"))?.Code;
                        isHibernated = powerState == "PowerState/stopped" || powerState == "PowerState/deallocated";
                    }
                } catch (Exception ex) {
                    log.LogWarning(ex, $"Error checking hibernation state of VM {vmName}. Will attempt to start it anyway.");
                }

                if (isHibernated) {
                    log.LogInformation($"VM {vmName} appears to be hibernated. Starting it up...");
                    try {
                        await vm.PowerOnAsync(WaitUntil.Completed); // This will resume from hibernation if the VM was hibernated
                        log.LogInformation($"Successfully started VM {vmName} from hibernation.");
                    } catch (Exception ex) {
                        log.LogWarning(ex, $"Error resuming VM {vmName} from hibernation. Will continue and hope it starts normally.");
                    }
                } else {
                    log.LogInformation($"VM {vmName} is not in a hibernated state. It should be running already.");
                }
                
                // Run a quick RDP service activation on a separate thread to help speed up availability
                _ = Task.Run(async () => {
                    try {
                        log.LogInformation($"Running proactive RDP service check and activation for {vmName}...");
                        var proactiveScript = @"$s = Get-Service -Name 'TermService' -EA SilentlyContinue; if ($s) { Start-Service -Name 'TermService' -Force; Set-Service -Name 'TermService' -StartupType Automatic; Write-Output 'PREEMPTIVE_RDP_SERVICE_START' } else { Write-Output 'RDP_SERVICE_NOT_FOUND' }";
                        var cmdInput = new RunCommandInput("RunPowerShellScript");
                        cmdInput.Script.Add(proactiveScript);
                        await vm.RunCommandAsync(WaitUntil.Started, cmdInput);
                    } catch (Exception ex) {
                        log.LogWarning(ex, $"Could not run proactive RDP service start for {vmName}");
                    }
                });
                
                
                log.LogInformation($"Waiting for VM {vmName} to complete boot process and initialize RDP service...");
                int attempts = 0, maxAttempts = 20; // Reduced from 40 to 20 attempts
                bool isRdpReady = false;
                while (!isRdpReady && attempts < maxAttempts)
                {
                    try
                    {
                        using var tcpClient = new TcpClient();
                        var connectTask = tcpClient.ConnectAsync(targetVmPrivateIp, 3389);
                        // Reduce timeout from 5000ms to 3000ms
                        if (await Task.WhenAny(connectTask, Task.Delay(3000)) == connectTask && connectTask.IsCompletedSuccessfully) {
                            isRdpReady = true;
                            log.LogInformation($"RDP port on {vmName} ({targetVmPrivateIp}) is responding after {attempts + 1} attempts.");
                            tcpClient.Close();
                        } else if (connectTask.IsFaulted) { throw connectTask.Exception?.InnerException ?? new SocketException((int)SocketError.ConnectionRefused); }
                        else { throw new TimeoutException($"Connection attempt {attempts + 1}/{maxAttempts} timed out."); }
                    }
                    catch (Exception ex)
                    {
                        attempts++;
                        log.LogInformation($"Waiting for RDP service on {vmName}... Attempt {attempts}/{maxAttempts} - ({ex.GetType().Name})");
                        if (attempts >= maxAttempts) break;
                        // Reduce delay between attempts from 6000ms to 3000ms
                        await Task.Delay(3000);

                        // RDP Service Check via RunCommand (only at half attempts)
                        if (attempts == maxAttempts / 4 || attempts == maxAttempts / 2)
                        {
                            log.LogInformation($"Running service check script at attempt {attempts}/{maxAttempts} for {vmName}...");
                            try
                            {
                                // Enhanced script to not only check but also ensure RDP service is running
                                var checkScript = @"$s = Get-Service -Name 'TermService' -EA SilentlyContinue; if ($s) { if ($s.Status -ne 'Running') { Start-Service -Name 'TermService' -Force; Write-Output 'RDP_SERVICE_STARTED' } else { Write-Output 'RDP_SERVICE_RUNNING' } } else { Write-Output 'RDP_SERVICE_NOT_FOUND' }";
                                var cmdInput = new RunCommandInput("RunPowerShellScript");
                                cmdInput.Script.Add(checkScript);

                                ArmOperation<VirtualMachineRunCommandResult> cmdResultOperation = await vm.RunCommandAsync(WaitUntil.Completed, cmdInput);

                                // Access Value property of ArmOperation<T> to get VirtualMachineRunCommandResult
                                VirtualMachineRunCommandResult? runResult = cmdResultOperation.Value;
                                IReadOnlyList<InstanceViewStatus>? statuses = runResult?.Value; // Access Value property of VirtualMachineRunCommandResult
                                string? outputText = statuses?.FirstOrDefault()?.Message?.Trim();

                                if (outputText == "RDP_SERVICE_RUNNING") { log.LogInformation($"RDP service on {vmName} confirmed RUNNING via RunCommand."); }
                                else { log.LogWarning($"RDP service on {vmName} status via RunCommand: {outputText ?? "No Output"}."); }
                            }
                            catch (Exception cmdEx) { log.LogWarning(cmdEx, $"Could not check RDP service status on {vmName} via RunCommand."); }
                        }
                    }
                }

                // Always use the default password
                randomPassword = "Rt@wqPP7ZvUgtS7"; // Default password
                log.LogInformation($"Using default password for VM {vmName}");
                
                // --- Prepare Guacamole token authentication ---
                log.LogInformation($"Preparing Guacamole connection for VM {vmName} ({targetVmPrivateIp})...");
                string tokenUrl = $"{guacamoleApiBaseUrl.TrimEnd('/')}/api/tokens";
                log.LogInformation($"Attempting Guac auth token: POST {tokenUrl}");
                string? authToken = null;
                string? dataSource = null;
                try
                {
                    var tokenRequestContent = new FormUrlEncodedContent(new[] { 
                        new KeyValuePair<string, string>("username", guacamoleApiUsername), 
                        new KeyValuePair<string, string>("password", guacamoleApiPassword) 
                    });
                    using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl) { Content = tokenRequestContent };
                    var tokenResponse = await httpClient.SendAsync(request);
                    string tokenResponseBody = await tokenResponse.Content.ReadAsStringAsync();
                    if (tokenResponse.IsSuccessStatusCode) {
                        var tokenData = JObject.Parse(tokenResponseBody);
                        authToken = tokenData["authToken"]?.ToString();
                        dataSource = tokenData["dataSource"]?.ToString();
                        if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(dataSource)) { 
                            log.LogError($"Guac token API OK but missing data. Resp: {tokenResponseBody}"); 
                        }
                        else { 
                            log.LogInformation($"Guac auth token acquired for datasource '{dataSource}'."); 
                        }
                    } else { 
                        log.LogError($"Error getting Guac token: {tokenResponse.StatusCode} - {tokenResponseBody}"); 
                    }
                } catch (Exception ex) { 
                    log.LogError(ex, $"Exception during Guac token API call: {ex.ToString()}"); 
                }

                if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(dataSource))
                {
                    log.LogError("Failed to retrieve Guacamole auth token. Cannot register VM.");
                    var authErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    authErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    authErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await authErrorResponse.WriteStringAsync("Failed to authenticate with Guacamole server to register VM.");
                    return authErrorResponse;
                }

                // Determine which user account to assign based on round-robin strategy
                string targetUsername = GetNextAvailableUserAccount(log);
                log.LogInformation($"Assigning user to {targetUsername} for VM {vmName}");
                
                string? guacamoleConnectionId = await CreateGuacamoleConnection(vmName, targetVmPrivateIp, targetUsername, 
                                                                             randomPassword, guacamoleApiBaseUrl, authToken, dataSource, log);

                if (string.IsNullOrEmpty(guacamoleConnectionId))
                {
                    log.LogError($"Failed to register VM {vmName} with Guacamole.");
                    var guacErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    guacErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    guacErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await guacErrorResponse.WriteStringAsync("Failed to register VM with Guacamole.");
                    return guacErrorResponse;
                }
                log.LogInformation($"Successfully registered Guacamole connection for {vmName}. Encoded ID: {guacamoleConnectionId}");

                // Only schedule hibernation for newly created VMs, not VMs from the warm pool
                if (!vmName.StartsWith("SolidCAM-VM-Pool-"))
                {
                    // Schedule the VM for hibernation after 60 seconds
                    _ = Task.Run(async () => {
                        try {
                            log.LogInformation($"VM {vmName} will be hibernated in 60 seconds...");
                            await Task.Delay(TimeSpan.FromSeconds(60));
                            log.LogInformation($"Starting hibernation of VM {vmName}...");
                            // Use PowerOff with hibernate=true to hibernate the VM
                            await vm.PowerOffAsync(WaitUntil.Completed, skipShutdown: true);
                            log.LogInformation($"Successfully hibernated VM {vmName}");
                        }
                        catch (Exception ex) {
                            log.LogError(ex, $"Failed to hibernate VM {vmName}: {ex.Message}");
                            log.LogInformation($"Attempting to deallocate VM {vmName} as fallback...");
                            try {
                                await vm.DeallocateAsync(WaitUntil.Completed);
                                log.LogInformation($"Successfully deallocated VM {vmName} as fallback");
                            } catch (Exception deallocEx) {
                                log.LogError(deallocEx, $"Failed to deallocate VM {vmName} as fallback: {deallocEx.Message}");
                            }
                        }
                    });
                }

                // --- Return Success Response ---
                log.LogInformation($"VM deployment sequence complete for {vmName}. Returning Guacamole connection ID and auth token.");
                var responseOk = req.CreateResponse(HttpStatusCode.OK);
                responseOk.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                responseOk.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseOk.WriteAsJsonAsync(new {
                    vmName = vmName,
                    guacamoleConnectionId = guacamoleConnectionId,
                    guacamoleAuthToken = authToken,
                    resourceGroup = vm.Id?.ResourceGroupName ?? "Unknown",
                    vmUsername = targetUsername,
                    vmPassword = randomPassword,
                    vmSize = vm.Data?.HardwareProfile?.VmSize?.ToString() ?? "Unknown",
                    provisioningDurationEstimate = $"{attempts * 3} seconds"
                });
                return responseOk;
            }
            catch (Exception ex)
            {
                var responseCatch = req.CreateResponse(HttpStatusCode.InternalServerError);
                responseCatch.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                responseCatch.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseCatch.WriteAsJsonAsync(new { error = $"An unexpected server error occurred: {ex.Message}" });
                return responseCatch;
            }
        }

        // Create Guacamole Connection
        private static async Task<string?> CreateGuacamoleConnection(string connectionName, string targetIpAddress, 
                                                                string targetUsername, string targetPassword, 
                                                                string guacamoleApiBaseUrl, string authToken, 
                                                                string dataSource, ILogger log)
        {
            string createConnectionUrl = $"{guacamoleApiBaseUrl.TrimEnd('/')}/api/session/data/{dataSource}/connections?token={authToken}";
            var connectionPayload = new JObject(
                new JProperty("parentIdentifier", "ROOT"), 
                new JProperty("name", connectionName), 
                new JProperty("protocol", "rdp"),
                new JProperty("parameters", new JObject(
                    new JProperty("hostname", targetIpAddress), 
                    new JProperty("port", "3389"),
                    new JProperty("username", targetUsername), 
                    new JProperty("password", targetPassword),
                    new JProperty("ignore-cert", "true"), 
                    new JProperty("security", "nla"),
                    new JProperty("resize-method", "display-update"), 
                    new JProperty("enable-drive", "false"),
                    new JProperty("enable-wallpaper", "false"), 
                    new JProperty("enable-theming", "false"),
                    new JProperty("enable-font-smoothing", "true"), 
                    new JProperty("enable-full-window-drag", "false"),
                    new JProperty("enable-desktop-composition", "false"), 
                    new JProperty("enable-menu-animations", "false"),
                    new JProperty("disable-bitmap-caching", "false"), 
                    new JProperty("disable-offscreen-caching", "false")
                )), 
                new JProperty("attributes", new JObject())
            );

            log.LogInformation($"Attempting to create Guacamole connection: POST {createConnectionUrl.Split('?')[0]}?token=...");
            try {
                using (var request = new HttpRequestMessage(HttpMethod.Post, createConnectionUrl)) {
                    request.Content = new StringContent(connectionPayload.ToString(), Encoding.UTF8, "application/json");
                    var response = await httpClient.SendAsync(request);
                    string responseBody = await response.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode) {
                        log.LogInformation($"Guac Create Connection Response: {response.StatusCode}");
                        var createdConnection = JObject.Parse(responseBody);
                        string? identifier = createdConnection["identifier"]?.ToString();
                        if (string.IsNullOrEmpty(identifier)) { 
                            log.LogError($"Guac connection create OK but missing 'identifier' in response: {responseBody}"); 
                            return null; 
                        }
                        string rawIdentifierForUrl = $"{identifier}\0c\0{dataSource}";
                        string encodedIdentifier = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawIdentifierForUrl))
                            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
                        log.LogInformation($"Guac connection created: Identifier='{identifier}', DataSource='{dataSource}', Encoded='{encodedIdentifier}'");
                        return encodedIdentifier;
                    } else { 
                        log.LogError($"Error creating Guac connection: {response.StatusCode} - Body: {responseBody}"); 
                        return null; 
                    }
                }
            } catch (Exception ex) { 
                log.LogError(ex, $"Exception during Guac create connection API call: {ex.ToString()}"); 
                return null; 
            }
        }

        // Assign users to different operator accounts in a round-robin fashion
        // Assign users to different operator accounts in a round-robin fashion
        private static int currentOperatorIndex = 0;
        private static readonly object operatorIndexLock = new object();

        private static string GetNextAvailableUserAccount(ILogger log)
        {
            lock (operatorIndexLock)
            {
                // Increment and wrap around using only accounts 1-3
                currentOperatorIndex = (currentOperatorIndex % 3) + 1;
                string username = $"SolidCAMOperator{currentOperatorIndex}";
                log.LogInformation($"Allocated user account {username} (index: {currentOperatorIndex})");
                return username;
            }
        }
    }
}