using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Azure.Storage.Blobs.Models; // Add this line for BlobUploadOptions
using Azure; // Add this line for RequestFailedException and ETag

namespace DeployVMFunction
{
    public class DistributedLock : IAsyncDisposable
    {
        private readonly BlobLeaseClient _leaseClient;
        private readonly ILogger _logger;
        private string _leaseId;
        private bool _leaseAcquired = false;

        public DistributedLock(string connectionString, string containerName, string blobName, ILogger logger)
        {
            _logger = logger;
            var blobServiceClient = new BlobServiceClient(connectionString);
            var containerClient = blobServiceClient.GetBlobContainerClient(containerName);
            
            // Ensure container exists
            containerClient.CreateIfNotExists();
            
            var blobClient = containerClient.GetBlobClient(blobName);
            
            // Check if blob exists first without trying to modify it
            if (!blobClient.Exists())
            {
                try {
                    // Attempt to create blob if it doesn't exist
                    blobClient.Upload(new BinaryData(Array.Empty<byte>()), new BlobUploadOptions { 
                        Conditions = new BlobRequestConditions { IfNoneMatch = new ETag("*") }
                    });
                    logger.LogInformation("Created lock blob for the first time");
                }
                catch (RequestFailedException ex) when (ex.ErrorCode == "BlobAlreadyExists") {
                    // This is fine, another instance created it first
                    logger.LogInformation("Lock blob already exists, using existing blob");
                }
            }
            else
            {
                logger.LogInformation("Lock blob already exists, using existing blob");
            }
            
            _leaseClient = blobClient.GetBlobLeaseClient();
        }

        public async Task<bool> AcquireAsync(int leaseDurationSeconds = 30)
        {
            try
            {
                // Use only 15 seconds lease time - the minimum allowed
                _leaseId = (await _leaseClient.AcquireAsync(TimeSpan.FromSeconds(15))).Value.LeaseId;
                _leaseAcquired = true;
                _logger.LogInformation($"Acquired lock with lease ID: {_leaseId}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to acquire lock: {ex.Message}");
                return false;
            }
        }

        public async Task ReleaseAsync()
        {
            if (_leaseAcquired)
            {
                try
                {
                    await _leaseClient.ReleaseAsync();
                    _leaseAcquired = false;
                    _logger.LogInformation($"Released lock with lease ID: {_leaseId}");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Error releasing lock: {ex.Message}");
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await ReleaseAsync();
        }
    }
}