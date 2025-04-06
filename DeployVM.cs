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
using System.Security.Cryptography; // Used in GenerateSecurePassword
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

                log.LogInformation("Generating a secure random password for SolidCAMOperator account");
                Task<string> passwordGenerationTask = Task.Run(() => GenerateSecurePassword(16));

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

                log.LogInformation($"Waiting for VM {vmName} to complete boot process and initialize RDP service...");
                int attempts = 0, maxAttempts = 40;
                bool isRdpReady = false;
                while (!isRdpReady && attempts < maxAttempts)
                {
                    try
                    {
                        using var tcpClient = new TcpClient();
                        var connectTask = tcpClient.ConnectAsync(targetVmPrivateIp, 3389);
                        if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask && connectTask.IsCompletedSuccessfully) {
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
                        await Task.Delay(6000);

                        // RDP Service Check via RunCommand (only at half attempts)
                        if (attempts == maxAttempts / 2)
                        {
                            log.LogInformation($"Halfway through RDP polling attempts for {vmName}. Running service check script...");
                            try
                            {
                                var checkScript = @"$s = Get-Service -Name 'TermService' -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Write-Output 'RDP_SERVICE_RUNNING' } else { Write-Output 'RDP_SERVICE_NOT_RUNNING' }";
                                var cmdInput = new RunCommandInput("RunPowerShellScript");
                                cmdInput.Script.Add(checkScript);

                                // --- Fix for CS0029 (Error 1) ---
                                // Change type from Response<T> to ArmOperation<T>
                                ArmOperation<VirtualMachineRunCommandResult> cmdResultOperation = await vm.RunCommandAsync(WaitUntil.Completed, cmdInput);
                                // --- End Fix ---

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

                if (!isRdpReady) { log.LogWarning($"VM {vmName} RDP service did not become responsive. Proceeding anyway..."); }

                string randomPassword = await passwordGenerationTask;

                // --- Execute Password Reset Script with Detailed Logging ---
                try
                {
                    string psScript = @"$p = ConvertTo-SecureString '" + randomPassword + @"' -AsPlainText -Force; $u = 'SolidCAMOperator'; try { Write-Output 'Getting user...'; $e = Get-LocalUser -Name $u -EA SilentlyContinue; if ($e) { Write-Output 'Setting pwd...'; Set-LocalUser -Name $u -Password $p -AccountNeverExpires -PasswordNeverExpires $true; Write-Output 'Set pwd done.'; } else { Write-Output 'Creating user...'; New-LocalUser -Name $u -Password $p -AccountNeverExpires -PasswordNeverExpires $true; Write-Output 'Create user done.'; } Write-Output 'Enabling user...'; Enable-LocalUser -Name $u; Write-Output 'Enable done.'; Write-Output 'Adding group member...'; Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $u -EA SilentlyContinue; Write-Output 'Add group done.'; Write-Output 'Success.'; } catch { Write-Error ""ERR: $($_.Exception.Message)""; Write-Error ""Trace: $($_.ScriptStackTrace)""; }";
                    var runCommandInput = new RunCommandInput("RunPowerShellScript");
                    runCommandInput.Script.Add(psScript);

                    var commandStartTime = DateTime.UtcNow;
                    log.LogInformation($"[{commandStartTime:O}] START executing PowerShell password reset script on VM {vmName}.");

                    // --- Fix for CS0029 (Error 2) ---
                    // Change type from Response<T> to ArmOperation<T>
                    ArmOperation<VirtualMachineRunCommandResult>? passwordResetOperation = null;
                    try
                    {
                         passwordResetOperation = await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
                    }
                    catch (Exception runCmdEx) { log.LogError(runCmdEx, $"Exception thrown DIRECTLY by vm.RunCommandAsync for password reset on {vmName}."); throw; }
                    // --- End Fix ---

                    var commandEndTime = DateTime.UtcNow;
                    var commandDuration = commandEndTime - commandStartTime;
                    log.LogInformation($"[{commandEndTime:O}] FINISHED executing PowerShell password reset script on VM {vmName}. Duration: {commandDuration.TotalSeconds:F2} seconds.");

                    // --- Fix for CS0119 / CS0446 (uses corrected type from above) ---
                    // Access Value property of ArmOperation<T> first
                    VirtualMachineRunCommandResult? passwordResetResult = passwordResetOperation?.Value;
                    // Then access Value property of VirtualMachineRunCommandResult (the list)
                    if (passwordResetResult?.Value != null && passwordResetResult.Value.Any())
                    {
                        log.LogInformation($"--- Script Output/Error Messages for VM {vmName} ---");
                        // Loop over the inner list: passwordResetResult.Value
                        foreach (var status in passwordResetResult.Value)
                        {
                             log.LogInformation($"Script Msg: Level='{status.Level}', Code='{status.Code}', DisplayStatus='{status.DisplayStatus}', Message='{status.Message?.Trim()}'");
                        }
                        log.LogInformation($"--- End Script Output/Error Messages ---");
                    }
                    else if (passwordResetResult != null) { log.LogWarning($"Password reset script executed for VM {vmName}, but no detailed output messages returned (List was null or empty)."); }
                    else { log.LogWarning($"Password reset script execution result or its value was null for VM {vmName}."); }
                    // --- End Fix ---
                }
                catch (Exception ex) { log.LogError(ex, $"Outer catch block: Error during password reset process for VM {vmName}."); }

                // --- Prepare Guacamole token authentication ---
                log.LogInformation($"Preparing Guacamole connection for VM {vmName} ({targetVmPrivateIp})...");
                string tokenUrl = $"{guacamoleApiBaseUrl.TrimEnd('/')}/api/tokens";
                log.LogInformation($"Attempting Guac auth token: POST {tokenUrl}");
                string? authToken = null;
                string? dataSource = null;
                try
                {
                    var tokenRequestContent = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("username", guacamoleApiUsername), new KeyValuePair<string, string>("password", guacamoleApiPassword) });
                    using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl) { Content = tokenRequestContent };
                    var tokenResponse = await httpClient.SendAsync(request);
                    string tokenResponseBody = await tokenResponse.Content.ReadAsStringAsync();
                    if (tokenResponse.IsSuccessStatusCode) {
                        var tokenData = JObject.Parse(tokenResponseBody);
                        authToken = tokenData["authToken"]?.ToString();
                        dataSource = tokenData["dataSource"]?.ToString();
                        if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(dataSource)) { log.LogError($"Guac token API OK but missing data. Resp: {tokenResponseBody}"); }
                        else { log.LogInformation($"Guac auth token acquired for datasource '{dataSource}'."); }
                    } else { log.LogError($"Error getting Guac token: {tokenResponse.StatusCode} - {tokenResponseBody}"); }
                } catch (Exception ex) { log.LogError(ex, $"Exception during Guac token API call: {ex.ToString()}"); }

                if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(dataSource))
                {
                    log.LogError("Failed to retrieve Guacamole auth token. Cannot register VM.");
                    var authErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    authErrorResponse.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    authErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await authErrorResponse.WriteStringAsync("Failed to authenticate with Guacamole server to register VM.");
                    return authErrorResponse;
                }

                string? guacamoleConnectionId = await CreateGuacamoleConnection(vmName, targetVmPrivateIp, "SolidCAMOperator", randomPassword, guacamoleApiBaseUrl, authToken, dataSource, log);

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

                // Only schedule deallocation for newly created VMs, not VMs from the warm pool
                if (!vmName.StartsWith("SolidCAM-VM-Pool-"))
                {
                    // Schedule the VM for deallocation after 60 seconds
                    _ = Task.Run(async () => {
                        try {
                            log.LogInformation($"VM {vmName} will be deallocated in 60 seconds...");
                            await Task.Delay(TimeSpan.FromSeconds(60));
                            log.LogInformation($"Starting deallocation of VM {vmName}...");
                            await vm.DeallocateAsync(WaitUntil.Completed);
                            log.LogInformation($"Successfully deallocated VM {vmName}");
                        }
                        catch (Exception ex) {
                            log.LogError(ex, $"Failed to deallocate VM {vmName}: {ex.Message}");
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
                    vmUsername = "SolidCAMOperator",
                    vmPassword = randomPassword,
                    vmSize = vm.Data?.HardwareProfile?.VmSize?.ToString() ?? "Unknown",
                    provisioningDurationEstimate = $"{attempts * 6} seconds"
                });
                return responseOk;
            }
            catch (Exception ex)
            {
                log.LogError(ex, $"Unhandled error during VM deployment function execution: {ex.ToString()}");
                var responseCatch = req.CreateResponse(HttpStatusCode.InternalServerError);
                responseCatch.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                responseCatch.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseCatch.WriteAsJsonAsync(new { error = $"An unexpected server error occurred: {ex.Message}" });
                return responseCatch;
            }
        }

        // Generate a secure random password
        private static string GenerateSecurePassword(int length)
        {
            const string uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
            const string lowercaseChars = "abcdefghijkmnpqrstuvwxyz";
            const string numericChars = "23456789";
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
            var allChars = uppercaseChars + lowercaseChars + numericChars + specialChars;
            var password = new char[length];
            var requiredChars = new List<char> {
                uppercaseChars[RandomNumberGenerator.GetInt32(uppercaseChars.Length)],
                lowercaseChars[RandomNumberGenerator.GetInt32(lowercaseChars.Length)],
                numericChars[RandomNumberGenerator.GetInt32(numericChars.Length)],
                specialChars[RandomNumberGenerator.GetInt32(specialChars.Length)]
            };
            if (length < requiredChars.Count) throw new ArgumentException("Password length too short.", nameof(length));
            for (int i = 0; i < requiredChars.Count; i++) password[i] = requiredChars[i];
            for (int i = requiredChars.Count; i < length; i++) password[i] = allChars[RandomNumberGenerator.GetInt32(allChars.Length)];
            for (int i = password.Length - 1; i > 0; i--) { int j = RandomNumberGenerator.GetInt32(i + 1); (password[i], password[j]) = (password[j], password[i]); }
            return new string(password);
        }

        // Create Guacamole Connection
        private static async Task<string?> CreateGuacamoleConnection(string connectionName, string targetIpAddress, string targetUsername, string targetPassword, string guacamoleApiBaseUrl, string authToken, string dataSource, ILogger log)
        {
            string createConnectionUrl = $"{guacamoleApiBaseUrl.TrimEnd('/')}/api/session/data/{dataSource}/connections?token={authToken}";
            var connectionPayload = new JObject( /* ... JObject definition as before ... */
                 new JProperty("parentIdentifier", "ROOT"), new JProperty("name", connectionName), new JProperty("protocol", "rdp"),
                 new JProperty("parameters", new JObject(
                     new JProperty("hostname", targetIpAddress), new JProperty("port", "3389"),
                     new JProperty("username", targetUsername), new JProperty("password", targetPassword),
                     new JProperty("ignore-cert", "true"), new JProperty("security", "nla"),
                     new JProperty("resize-method", "display-update"), new JProperty("enable-drive", "false"),
                     new JProperty("enable-wallpaper", "false"), new JProperty("enable-theming", "false"),
                     new JProperty("enable-font-smoothing", "true"), new JProperty("enable-full-window-drag", "false"),
                     new JProperty("enable-desktop-composition", "false"), new JProperty("enable-menu-animations", "false"),
                     new JProperty("disable-bitmap-caching", "false"), new JProperty("disable-offscreen-caching", "false")
                  )), new JProperty("attributes", new JObject())); // Keep attributes simple unless needed

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
                        if (string.IsNullOrEmpty(identifier)) { log.LogError($"Guac connection create OK but missing 'identifier' in response: {responseBody}"); return null; }
                        string rawIdentifierForUrl = $"{identifier}\0c\0{dataSource}";
                        string encodedIdentifier = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawIdentifierForUrl)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
                        log.LogInformation($"Guac connection created: Identifier='{identifier}', DataSource='{dataSource}', Encoded='{encodedIdentifier}'");
                        return encodedIdentifier;
                    } else { log.LogError($"Error creating Guac connection: {response.StatusCode} - Body: {responseBody}"); return null; }
                }
            } catch (Exception ex) { log.LogError(ex, $"Exception during Guac create connection API call: {ex.ToString()}"); return null; }
        }
    }
}