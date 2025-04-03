using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.ResourceManager.Resources;
using Azure.Core;
using Azure;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Net;
using System.Security.Cryptography;

namespace DeployVMFunction
{
    public static class DeployVM
    {
        // Define a static HttpClient to reuse connections
        private static readonly HttpClient httpClient = new HttpClient();

        [Function("DeployVM")]
        public static async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req)
        {
            // Get logger from FunctionContext
            var log = req.FunctionContext.GetLogger("DeployVM");
            log.LogInformation("C# HTTP trigger function processed a request for VM deployment (ISOLATED WORKER).");

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

            try
            {
                // --- Configuration from Environment Variables ---
                string? guacamoleServerPrivateIp = Environment.GetEnvironmentVariable("GUACAMOLE_SERVER_PRIVATE_IP");
                string? guacamoleApiBaseUrl = Environment.GetEnvironmentVariable("GUACAMOLE_API_BASE_URL");

                if (string.IsNullOrEmpty(guacamoleServerPrivateIp) || string.IsNullOrEmpty(guacamoleApiBaseUrl))
                {
                    log.LogError("Missing required environment variables: GUACAMOLE_SERVER_PRIVATE_IP, GUACAMOLE_API_BASE_URL");
                    var configErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    // Add CORS headers
                    configErrorResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                    configErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await configErrorResponse.WriteStringAsync("Server configuration error: Missing required environment variables.");
                    return configErrorResponse;
                }
                log.LogInformation($"Using Guacamole Server Private IP: {guacamoleServerPrivateIp}");
                log.LogInformation($"Using Guacamole API Base URL: {guacamoleApiBaseUrl}");
                // Username/Password read inside helper

                // --- Azure Resource Setup ---
                var credential = new DefaultAzureCredential();
                var armClient = new ArmClient(credential);

                var subscription = await armClient.GetDefaultSubscriptionAsync();
                ResourceGroupResource resourceGroup = await subscription.GetResourceGroupAsync("SolidCAM-Golden-Image_group");
                AzureLocation location = AzureLocation.NorthEurope; // Use AzureLocation type

                log.LogInformation("Getting existing VNet: SolidCAM-Golden-Image-vnet and subnet: default");
                VirtualNetworkResource existingVnet = await resourceGroup.GetVirtualNetworks().GetAsync("SolidCAM-Golden-Image-vnet");
                SubnetResource subnet = await existingVnet.GetSubnets().GetAsync("default");
                log.LogInformation($"Using Subnet ID: {subnet.Id}");

                string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
                string vmName = $"SolidCAM-VM-{timestamp}";
                string nicName = $"vm-nic-{timestamp}";
                string nsgName = $"vm-nsg-{timestamp}";

                log.LogInformation($"Creating NSG for target VM {vmName}: {nsgName}");
                var nsgData = new NetworkSecurityGroupData()
                {
                    Location = location,
                    SecurityRules =
                    {
                        new SecurityRuleData()
                        {
                            Name = "AllowRDP_From_Guacamole", Priority = 1000, Access = SecurityRuleAccess.Allow, Direction = SecurityRuleDirection.Inbound,
                            Protocol = SecurityRuleProtocol.Tcp, SourceAddressPrefix = guacamoleServerPrivateIp, SourcePortRange = "*",
                            DestinationAddressPrefix = "*", DestinationPortRange = "3389"
                        }
                    }
                };
                var nsgCollection = resourceGroup.GetNetworkSecurityGroups();
                var nsgCreateOp = await nsgCollection.CreateOrUpdateAsync(WaitUntil.Completed, nsgName, nsgData);
                NetworkSecurityGroupResource nsg = nsgCreateOp.Value;
                log.LogInformation($"NSG created: {nsg.Id}");

                log.LogInformation($"Creating network interface {nicName} in subnet {subnet.Id}");
                var nicData = new NetworkInterfaceData()
                {
                    Location = location,
                    NetworkSecurityGroup = new NetworkSecurityGroupData() { Id = nsg.Id },
                    IPConfigurations = { new NetworkInterfaceIPConfigurationData() { Name = "ipconfig1", Primary = true, Subnet = new SubnetData() { Id = subnet.Id }, PrivateIPAllocationMethod = NetworkIPAllocationMethod.Dynamic } }
                };
                var nicCollection = resourceGroup.GetNetworkInterfaces();
                var nicCreateOp = await nicCollection.CreateOrUpdateAsync(WaitUntil.Completed, nicName, nicData);
                NetworkInterfaceResource nic = nicCreateOp.Value;
                log.LogInformation($"NIC created: {nic.Id}");

                log.LogInformation("Retrieving created NIC to get Private IP...");
                await Task.Delay(5000);
                var createdNic = await nicCollection.GetAsync(nicName);
                string? targetVmPrivateIp = createdNic.Value.Data.IPConfigurations?.FirstOrDefault()?.PrivateIPAddress;

                if (string.IsNullOrEmpty(targetVmPrivateIp))
                {
                    log.LogError($"Could not retrieve private IP address for target VM NIC {nicName} after waiting.");
                    var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    // Add CORS headers
                    errorResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                    errorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await errorResponse.WriteStringAsync("Could not retrieve VM private IP address.");
                    return errorResponse;
                }
                log.LogInformation($"Target VM Private IP obtained: {targetVmPrivateIp}");

                log.LogInformation("Preparing VM configuration...");
                string galleryImageId = "/subscriptions/05329ba1-6d97-4b22-808c-9f448c4e9a11/resourceGroups/SolidCAM-Golden-Image_group/providers/Microsoft.Compute/galleries/solidcam_image_gallery/images/solidcam-golden-image/versions/1.0.0";
                var imageResourceId = new ResourceIdentifier(galleryImageId);

                var vmData = new VirtualMachineData(location)
                {
                    HardwareProfile = new VirtualMachineHardwareProfile() { VmSize = VirtualMachineSizeType.StandardD4SV3 },
                    NetworkProfile = new VirtualMachineNetworkProfile() { NetworkInterfaces = { new VirtualMachineNetworkInterfaceReference() { Id = nic.Id, Primary = true } } },
                    StorageProfile = new VirtualMachineStorageProfile() { ImageReference = new ImageReference() { Id = imageResourceId } },
                    SecurityProfile = new SecurityProfile() { SecurityType = SecurityType.TrustedLaunch }
                };

                log.LogInformation($"Creating VM: {vmName} using image {galleryImageId}");
                var vmCollection = resourceGroup.GetVirtualMachines();
                var vmCreateOp = await vmCollection.CreateOrUpdateAsync(WaitUntil.Completed, vmName, vmData);
                VirtualMachineResource vm = vmCreateOp.Value;
                log.LogInformation($"VM creation initiated/completed for: {vm.Data.Name}");

                // Wait for VM to fully boot before continuing
                log.LogInformation("Waiting for VM to complete boot process and initialize RDP service...");
                await Task.Delay(60000); // Wait 60 seconds for VM to fully boot

                // Generate a secure random password for the SolidCAMOperator account
                string randomPassword = GenerateSecurePassword(16);
                log.LogInformation("Generated a secure random password for SolidCAMOperator account");

                try
                {
                    // Create PowerShell script to reset the password
                    string psScript = @"
$password = ConvertTo-SecureString '" + randomPassword + @"' -AsPlainText -Force
$username = 'SolidCAMOperator'

# Check if user exists, if not, create it
try {
    $userExists = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if ($userExists) {
        # Update existing user
        Set-LocalUser -Name $username -Password $password -AccountNeverExpires -PasswordNeverExpires $true
    } else {
        # Create new user
        New-LocalUser -Name $username -Password $password -AccountNeverExpires -PasswordNeverExpires $true
    }

    # Ensure user is active
    Enable-LocalUser -Name $username

    # Add to Remote Desktop Users group
    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $username -ErrorAction SilentlyContinue
    
    Write-Output 'Password reset successful'
} catch {
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
}";

                    // Create the command input for the version of Azure SDK you're using
                    var runCommandInput = new RunCommandInput("RunPowerShellScript");
                    runCommandInput.Script.Add(psScript);

                    log.LogInformation("Executing PowerShell script to reset SolidCAMOperator password...");
                    await vm.RunCommandAsync(WaitUntil.Completed, runCommandInput);
                    log.LogInformation("Password reset command completed successfully");
                }
                catch (Exception ex)
                {
                    log.LogError($"Error executing password reset command: {ex.Message}");
                    // Continue anyway, we'll try with the SolidCAMOperator credentials we generated
                }

                // --- Register VM with Guacamole using SolidCAMOperator and the new password ---
                log.LogInformation($"Registering VM {vmName} ({targetVmPrivateIp}) with Guacamole using API token auth...");
                var (guacamoleConnectionId, guacamoleAuthToken) = await RegisterVmWithGuacamole(
                    vmName, targetVmPrivateIp, "SolidCAMOperator", randomPassword,
                    guacamoleApiBaseUrl, log
                );

                if (string.IsNullOrEmpty(guacamoleConnectionId) || string.IsNullOrEmpty(guacamoleAuthToken))
                {
                    log.LogError("Failed to register VM with Guacamole. Check Guacamole server logs and function configuration (API Username/Password).");
                    var guacErrorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                    // Add CORS headers
                    guacErrorResponse.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                    guacErrorResponse.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await guacErrorResponse.WriteStringAsync("Failed to register VM with Guacamole.");
                    return guacErrorResponse;
                }
                log.LogInformation($"Successfully registered Guacamole connection. Encoded ID: {guacamoleConnectionId}");

                // --- Return Success Response ---
                log.LogInformation($"VM deployment sequence complete for {vm.Data.Name}. Returning Guacamole connection ID and auth token.");
                var responseOk = req.CreateResponse(HttpStatusCode.OK);
                // Add CORS headers
                responseOk.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                responseOk.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseOk.WriteAsJsonAsync(new {
                    vmName = vm.Data.Name,
                    guacamoleConnectionId = guacamoleConnectionId,
                    guacamoleAuthToken = guacamoleAuthToken,
                    resourceGroup = "SolidCAM-Golden-Image_group",
                    vmUsername = "SolidCAMOperator",
                    vmPassword = randomPassword  // Including the password in the response
                });
                return responseOk;
            }
            catch (Exception ex)
            {
                log.LogError($"Error during VM deployment or Guacamole registration: {ex.ToString()}");
                var responseCatch = req.CreateResponse(HttpStatusCode.InternalServerError);
                // Add CORS headers
                responseCatch.Headers.Add("Access-Control-Allow-Origin", "https://solidcamportal743899.z16.web.core.windows.net");
                responseCatch.Headers.Add("Access-Control-Allow-Credentials", "true");
                await responseCatch.WriteAsJsonAsync(new { error = $"An unexpected error occurred: {ex.Message ?? "Unknown error"}" });
                return responseCatch;
            }
        }

        // Generate a secure random password
        private static string GenerateSecurePassword(int length)
        {
            const string uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";  // excluded I and O as they can be confused
            const string lowercaseChars = "abcdefghijkmnpqrstuvwxyz";  // excluded l and o as they can be confused
            const string numericChars = "23456789";  // excluded 0 and 1 as they can be confused
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
            
            var random = new Random();
            var characterSet = uppercaseChars + lowercaseChars + numericChars + specialChars;
            
            // Ensure password has at least one of each type
            var password = new StringBuilder();
            password.Append(uppercaseChars[random.Next(0, uppercaseChars.Length)]);
            password.Append(lowercaseChars[random.Next(0, lowercaseChars.Length)]);
            password.Append(numericChars[random.Next(0, numericChars.Length)]);
            password.Append(specialChars[random.Next(0, specialChars.Length)]);
            
            // Fill the rest with random characters
            for (int i = 4; i < length; i++)
            {
                password.Append(characterSet[random.Next(0, characterSet.Length)]);
            }
            
            // Shuffle the password characters
            var passwordArray = password.ToString().ToCharArray();
            for (int i = 0; i < passwordArray.Length; i++)
            {
                int randomIndex = random.Next(0, passwordArray.Length);
                char temp = passwordArray[i];
                passwordArray[i] = passwordArray[randomIndex];
                passwordArray[randomIndex] = temp;
            }
            
            return new string(passwordArray);
        }

        private static async Task<(string? connectionId, string? authToken)> RegisterVmWithGuacamole(
            string connectionName, string targetIpAddress, string targetUsername, string targetPassword,
            string guacamoleApiBaseUrl, ILogger log)
        {
            string? guacamoleApiUsername = Environment.GetEnvironmentVariable("GUACAMOLE_API_USERNAME");
            string? guacamoleApiPassword = Environment.GetEnvironmentVariable("GUACAMOLE_API_PASSWORD");

            if (string.IsNullOrEmpty(guacamoleApiUsername) || string.IsNullOrEmpty(guacamoleApiPassword)) {
                log.LogError("Missing GUACAMOLE_API_USERNAME or GUACAMOLE_API_PASSWORD env vars.");
                return (null, null);
            }

            string? authToken = null;
            string? dataSource = null;
            
            string tokenUrl = $"{guacamoleApiBaseUrl.TrimEnd('/')}/api/tokens";
            log.LogInformation($"Attempting Guac auth token: {tokenUrl}");

            try {
                var tokenRequestContent = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("username", guacamoleApiUsername),
                    new KeyValuePair<string, string>("password", guacamoleApiPassword) 
                });
                
                using (var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl) { Content = tokenRequestContent }) {
                    var tokenResponse = await httpClient.SendAsync(request);
                    string tokenResponseBody = await tokenResponse.Content.ReadAsStringAsync();
                    
                    if (tokenResponse.IsSuccessStatusCode) {
                        var tokenData = JObject.Parse(tokenResponseBody);
                        authToken = tokenData["authToken"]?.ToString();
                        dataSource = tokenData["dataSource"]?.ToString();
                        
                        if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(dataSource)) {
                            log.LogError($"Guac token API OK but missing data. Resp: {tokenResponseBody}"); 
                            return (null, null); 
                        }
                        
                        log.LogInformation($"Guac auth token OK for datasource '{dataSource}'.");
                    } else {
                        log.LogError($"Error getting Guac token: {tokenResponse.StatusCode} - {tokenResponseBody}"); 
                        return (null, null); 
                    }
                }
            } catch (Exception ex) {
                log.LogError($"Exception during Guac token API call: {ex.ToString()}"); 
                return (null, null); 
            }

            if (authToken == null || dataSource == null) {
                log.LogError("AuthToken or DataSource became null unexpectedly after token retrieval.");
                return (null, null);
            }

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
                    new JProperty("drive-path", ""),
                    new JProperty("create-drive-path", "false"),
                    new JProperty("console", "false"),
                    new JProperty("initial-program", ""),
                    new JProperty("client-name", "Guacamole RDP Client"),
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

            log.LogInformation($"Attempting Guac connection create: {createConnectionUrl.Split('?')[0]}?token=...");
            
            try {
                using (var request = new HttpRequestMessage(HttpMethod.Post, createConnectionUrl)) {
                    request.Content = new StringContent(connectionPayload.ToString(), Encoding.UTF8, "application/json");
                    var response = await httpClient.SendAsync(request);
                    string responseBody = await response.Content.ReadAsStringAsync();
                    
                    if (response.IsSuccessStatusCode) {
                        log.LogInformation($"Guac Create Connection OK: {response.StatusCode}");
                        var createdConnection = JObject.Parse(responseBody);
                        string? identifier = createdConnection["identifier"]?.ToString(); 
                        
                        if (string.IsNullOrEmpty(identifier)) {
                            log.LogError("Guac connection create OK but missing identifier."); 
                            return (null, authToken); 
                        }
                        
                        string rawIdentifierForUrl = $"{identifier}\0c\0{dataSource}";
                        string encodedIdentifier = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawIdentifierForUrl));
                        log.LogInformation($"Guac connection created: Identifier='{identifier}', Encoded='{encodedIdentifier}'");
                        return (encodedIdentifier, authToken);
                    } else {
                        log.LogError($"Error creating Guac connection: {response.StatusCode} - {responseBody}"); 
                        return (null, authToken); 
                    }
                }
            } catch (Exception ex) {
                log.LogError($"Exception during Guac create connection API call: {ex.ToString()}"); 
                return (null, authToken); 
            }
        }
    }
}