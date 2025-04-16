using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Net;
using Newtonsoft.Json;

namespace DeployVMFunction
{
    public class ReleaseAccountRequest
    {
        public string? vmName { get; set; }
        public string? username { get; set; }
    }

    public static class ReleaseUserAccount
    {
        [Function("ReleaseUserAccount")]
        public static async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req)
        {
            var log = req.FunctionContext.GetLogger("ReleaseUserAccount");
            log.LogInformation("Processing request to release a user account on a VM.");

            string allowedOrigin = Environment.GetEnvironmentVariable("AllowedCorsOrigin") ?? "https://solidcamportal743899.z16.web.core.windows.net";

            // Handle CORS preflight request
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
                // Parse request
                ReleaseAccountRequest? data;
                try
                {
                    data = await req.ReadFromJsonAsync<ReleaseAccountRequest>();
                }
                catch (Exception ex)
                {
                    log.LogError(ex, "Error parsing request body");
                    var badRequest = req.CreateResponse(HttpStatusCode.BadRequest);
                    badRequest.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    badRequest.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await badRequest.WriteStringAsync("Invalid request format. Please provide vmName and username.");
                    return badRequest;
                }
                
                // Check required parameters
                if (string.IsNullOrEmpty(data?.vmName) || string.IsNullOrEmpty(data?.username))
                {
                    log.LogError("Missing required parameters: vmName or username");
                    var badRequest = req.CreateResponse(HttpStatusCode.BadRequest);
                    badRequest.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    badRequest.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await badRequest.WriteStringAsync("Missing required parameters: vmName or username");
                    return badRequest;
                }

                string vmName = data.vmName;
                string username = data.username;
                
                // Check username format
                if (!username.StartsWith("SolidCAMOperator"))
                {
                    log.LogError($"Invalid username format: {username}. Expected format: SolidCAMOperator[1-3]");
                    var badRequest = req.CreateResponse(HttpStatusCode.BadRequest);
                    badRequest.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    badRequest.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await badRequest.WriteStringAsync("Invalid username format. Expected format: SolidCAMOperator[1-3]");
                    return badRequest;
                }

                // Parse account number
                if (!int.TryParse(username.Replace("SolidCAMOperator", ""), out int accountNumber) ||
                    accountNumber < 1 || accountNumber > 3)
                {
                    log.LogError($"Invalid account number in username: {username}. Expected a number between 1-3.");
                    var badRequest = req.CreateResponse(HttpStatusCode.BadRequest);
                    badRequest.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    badRequest.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await badRequest.WriteStringAsync("Invalid account number. Expected a number between 1-3.");
                    return badRequest;
                }

                // Initialize the VM assignment tracker
                string? connectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
                if (string.IsNullOrEmpty(connectionString))
                {
                    log.LogError("Missing Azure Storage connection string");
                    var serverError = req.CreateResponse(HttpStatusCode.InternalServerError);
                    serverError.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    serverError.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await serverError.WriteStringAsync("Server configuration error: Missing storage connection string");
                    return serverError;
                }

                // Release the account
                try
                {
                    var assignmentTracker = new VMAssignmentTracker(log, connectionString);
                    await assignmentTracker.ReleaseAccountOnVMAsync(vmName, accountNumber);
                    
                    log.LogInformation($"Successfully released account {username} (account #{accountNumber}) on VM {vmName}");
                    
                    var response = req.CreateResponse(HttpStatusCode.OK);
                    response.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    response.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await response.WriteAsJsonAsync(new
                    {
                        status = "success",
                        message = $"User account {username} released on VM {vmName}"
                    });
                    return response;
                }
                catch (Exception ex)
                {
                    log.LogError(ex, $"Error releasing account {username} on VM {vmName}");
                    var serverError = req.CreateResponse(HttpStatusCode.InternalServerError);
                    serverError.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                    serverError.Headers.Add("Access-Control-Allow-Credentials", "true");
                    await serverError.WriteAsJsonAsync(new
                    {
                        status = "error",
                        message = $"Error releasing account: {ex.Message}"
                    });
                    return serverError;
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Unhandled exception in ReleaseUserAccount function");
                var serverError = req.CreateResponse(HttpStatusCode.InternalServerError);
                serverError.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
                serverError.Headers.Add("Access-Control-Allow-Credentials", "true");
                await serverError.WriteAsJsonAsync(new
                {
                    status = "error",
                    message = "An unexpected error occurred"
                });
                return serverError;
            }
        }
    }
}
