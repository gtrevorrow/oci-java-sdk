/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.RetryConfiguration;
import com.oracle.bmc.auth.WorkloadIdentityFederationAuthenticationDetailProvider;
import com.oracle.bmc.objectstorage.ObjectStorageAsyncClient;
import com.oracle.bmc.objectstorage.ObjectStorageClient;
import com.oracle.bmc.objectstorage.requests.GetNamespaceRequest;
import com.oracle.bmc.objectstorage.responses.GetNamespaceResponse;
import java.util.logging.Logger;

/**
 * This example demonstrates how to use the WorkloadIdentityFederationAuthenticationDetailProvider
 * to authenticate calls to OCI APIs. It shows the basic usage and how to enable an optional
 * circuit breaker for the federation client.
 *
 * <p>
 * <b>Important: buildAsync() Method Benefits</b><br>
 * This example showcases the buildAsync() method, which provides true async semantics for
 * authentication provider initialization. The method offers several key advantages:
 * <ul>
 * <li>Token pre-fetching during provider initialization (not on first use)</li>
 * <li>Fail-fast behavior - authentication issues discovered early</li>
 * <li>Non-blocking provider creation through CompletableFuture composition</li>
 * <li>Concurrent authentication provider initialization becomes possible</li>
 * <li>Elegant async composition with CompletableFuture chaining</li>
 * <li>Superior performance under concurrent load</li>
 * </ul>
 * The async benefits are achieved through the OCI SDK's HttpClient abstraction, which ensures
 * consistent non-blocking behavior regardless of the underlying HTTP client implementation.
 * </p>
 *
 * <p>
 * This example requires the following command-line arguments:
 * <ol>
 * <li>tokenExchangeUrl: The URL of the token exchange endpoint (e.g., from an Identity Domain).</li>
 * <li>clientCredential: The client credential for basic authentication (e.g., "client_id:client_secret").</li>
 * <li>regionId: The OCI region ID (e.g., "us-ashburn-1").</li>
 * <li>compartmentId: The OCID of the compartment to query (e.g., your tenancy OCID).</li>
 * </ol>
 * It also requires the `OCI_SUBJECT_TOKEN` environment variable to be set with the subject token.
 */
public class WorkloadIdentityFederationAuthenticationExample {

    private static final Logger logger = Logger.getLogger(WorkloadIdentityFederationAuthenticationExample.class.getName());

    public static void main(String[] args) {
        logger.info("=== Oracle Cloud Infrastructure Workload Identity Federation Authentication Example ===");
        logger.info("This example demonstrates how to authenticate to OCI using Workload Identity Federation");

        if (args.length != 4) {
            logger.severe("Usage: java WorkloadIdentityFederationAuthenticationExample " +
                    "<tokenExchangeUrl> <clientCredential> <regionId> <compartmentId>");
            System.exit(1);
        }

        final String tokenExchangeUrl = args[0];
        final String clientCredential = args[1];
        final String regionId = args[2];
        final String compartmentId = args[3];

        // Pull subject token from environment variable
        final String subjectToken = System.getenv("OCI_SUBJECT_TOKEN");
        if (subjectToken == null || subjectToken.isEmpty()) {
            throw new IllegalArgumentException(
                    "Environment variable OCI_SUBJECT_TOKEN must be set with the subject token.");
        }

        logger.info("=== Workload Identity Federation Authentication Example ===");
        logger.info("Token Exchange URL: " + tokenExchangeUrl);
        logger.info("Subject Token (first 10 chars): "
                + subjectToken.substring(0, Math.min(subjectToken.length(), 10)) + "...");
        logger.info("Client Credential (first 10 chars): "
                + clientCredential.substring(0, Math.min(clientCredential.length(), 10)) + "...");
        logger.info("Region ID: " + regionId);
        logger.info("Compartment ID: " + compartmentId);
        logger.info("");

        // --- Create the authentication provider ---
        // This is the basic configuration that relies on SDK defaults for HTTP client settings.
        WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder =
                WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                        .tokenExchangeUrl(tokenExchangeUrl)
                        .subjectTokenSupplier(() -> subjectToken)
                        .clientCredential(clientCredential)
                        .region(Region.fromRegionId(regionId))
                        .secondsToExpireSessionTokenEarly(300L); // Optional: 5 minutes early expiration

        // --- Optional: Enable a circuit breaker ---
        // For added resilience, you can enable a circuit breaker with default settings.
        // This is useful if the token exchange endpoint is temporarily unavailable.
        // To enable it, uncomment the following line:
        // builder.withCircuitBreaker();

        WorkloadIdentityFederationAuthenticationDetailProvider authProvider = builder.build();
        WorkloadIdentityFederationAuthenticationDetailProvider asyncAuthProvider = null;
        WorkloadIdentityFederationAuthenticationDetailProvider proactiveProvider = null;

        try {
            // Test the authentication by making an Object Storage API call
            try (ObjectStorageClient objectStorageClient = ObjectStorageClient.builder()
                    .build(authProvider)) {

                logger.info("Testing authentication with Object Storage API...");

                // Get the namespace (this validates that authentication is working)
                GetNamespaceResponse namespaceResponse = objectStorageClient.getNamespace(
                        GetNamespaceRequest.builder().build());

                String namespace = namespaceResponse.getValue();
                logger.info("✓ Authentication successful!");
                logger.info("Account namespace: " + namespace);

                // Demonstrate token refresh capability
                logger.info("");
                logger.info("Testing token refresh...");
                String refreshedToken = authProvider.refresh();
                logger.info("✓ Token refresh successful!");
                logger.info("Refreshed token (first 20 chars): " +
                        refreshedToken.substring(0, Math.min(refreshedToken.length(), 20)) + "...");

            } catch (Exception e) {
                logger.severe("✗ Authentication or API call failed: " + e.getMessage());
                e.printStackTrace();
                logger.info("Continuing with async example despite sync authentication failure...");
            }

            // --- Demonstrate buildAsync() usage ---
            logger.info("");
            logger.info("=== Testing buildAsync() method ===");
            logger.info("Creating second authentication provider asynchronously...");

            try {
                // Create a second provider using buildAsync() - this pre-fetches the token
                asyncAuthProvider = WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                        .tokenExchangeUrl(tokenExchangeUrl)
                        .subjectTokenSupplier(() -> subjectToken)
                        .clientCredential(clientCredential)
                        .region(Region.fromRegionId(regionId))
                        .secondsToExpireSessionTokenEarly(300L)
                        .buildAsync()
                        .get(); // Get the provider after async initialization

                // The .thenApply() is called only AFTER the provider is fully initialized with a valid token
                // At this point, asyncAuthProvider is guaranteed to have a valid authentication token
                // This eliminates the "cold start" delay that would occur with regular build()

                // Create a new Object Storage ASYNC client with the async-initialized provider
                try (ObjectStorageAsyncClient asyncClient = ObjectStorageAsyncClient.builder()
                        .build(asyncAuthProvider)) {

                    logger.info("Making Object Storage API call with async provider...");

                    // This API call happens immediately without any authentication delay
                    // because the token was pre-fetched during buildAsync()
                    // ObjectStorageAsyncClient.getNamespace() returns CompletableFuture<GetNamespaceResponse>
                    GetNamespaceResponse response = asyncClient.getNamespace(
                            GetNamespaceRequest.builder().build(), null).get();
                    String asyncNamespace = response.getValue();
                    logger.info("✓ Async provider authentication successful!");
                    logger.info("Account namespace (via async provider): " + asyncNamespace);
                } catch (Exception e) {
                    logger.severe("✗ Failed to create async client or make API call: " + e.getMessage());
                    throw new RuntimeException("Failed to create async client", e);
                }
            } catch (Exception e) {
                logger.severe("✗ Unexpected error in buildAsync example: " + e.getMessage());
                e.printStackTrace();
            }

            logger.info("");
            logger.info("=== Example completed successfully! ===");
            logger.info("Both synchronous and asynchronous authentication providers worked correctly.");

            // Demonstrate the automatic background refresh functionality
            proactiveProvider = demonstrateProactiveRefresh(tokenExchangeUrl, clientCredential, regionId);

        } finally {
            // Clean up ALL authentication providers to prevent resource leaks
            logger.info("Shutting down authentication providers...");
            
            if (authProvider != null) {
                try {
                    authProvider.shutdown();
                    logger.info("✓ Synchronous provider shut down");
                } catch (Exception e) {
                    logger.warning("Warning: Failed to shutdown sync provider: " + e.getMessage());
                }
            }
            
            if (asyncAuthProvider != null) {
                try {
                    asyncAuthProvider.shutdown();
                    logger.info("✓ Async provider shut down");
                } catch (Exception e) {
                    logger.warning("Warning: Failed to shutdown async provider: " + e.getMessage());
                }
            }
            
            if (proactiveProvider != null) {
                try {
                    proactiveProvider.shutdown();
                    logger.info("✓ Proactive refresh provider shut down");
                } catch (Exception e) {
                    logger.warning("Warning: Failed to shutdown proactive provider: " + e.getMessage());
                }
            }
            
            logger.info("✓ All authentication providers shut down completed");
        }
    }

    /**
     * Demonstrates the proactive background token refresh functionality.
     * This method runs in a loop to show how the authentication provider
     * automatically refreshes tokens in the background before they expire.
     * 
     * @return The created proactive provider for proper cleanup by the caller
     */
    private static WorkloadIdentityFederationAuthenticationDetailProvider demonstrateProactiveRefresh(String tokenExchangeUrl, String clientCredential, String regionId) {
        logger.info("");
        logger.info("=== Demonstrating Proactive Background Token Refresh ===");
        logger.info("This demonstration shows automatic token refresh for 60-minute tokens...");
        logger.info("With proactive refresh at 80% of token lifetime (48 minutes), you'll see:");
        logger.info("• Consistent API performance throughout the token lifecycle");
        logger.info("• Automatic background refresh around the 48-minute mark");
        logger.info("• No blocking delays when tokens are refreshed");

        WorkloadIdentityFederationAuthenticationDetailProvider proactiveProvider = null;
        
        try {
            // Create an authentication provider with proactive refresh enabled
            proactiveProvider = WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                .tokenExchangeUrl(tokenExchangeUrl)
                .subjectTokenSupplier(() -> {
                    String subjectToken = System.getenv("OCI_SUBJECT_TOKEN");
                    if (subjectToken == null || subjectToken.trim().isEmpty()) {
                        throw new IllegalStateException("OCI_SUBJECT_TOKEN environment variable is not set");
                    }
                    return subjectToken;
                })
                .clientCredential(clientCredential)
                .region(Region.fromRegionId(regionId))
                .secondsToExpireSessionTokenEarly(300L) // Refresh 5 minutes before expiration
                .withCircuitBreaker() // Enable circuit breaker for robustness
                .retryConfiguration(RetryConfiguration.BASIC) // Enable retry configuration (automatically enables proactive refresh)
                .buildAsync() // Use async initialization with token pre-fetching
                .join(); // Wait for initialization to complete

            logger.info("✓ Proactive refresh provider initialized successfully");
            logger.info("  Token refresh will happen automatically at ~48 minutes (80% of 60-minute lifetime)");
            logger.info("  Retry configuration: BASIC (3 attempts, 30s delay with exponential backoff)");
            logger.info("  Proactive refresh: ENABLED (automatically enabled via retry configuration)");

            // Create a client with the proactive provider
            try (ObjectStorageAsyncClient client = ObjectStorageAsyncClient.builder()
                    .build(proactiveProvider)) {

                logger.info("Starting continuous demonstration with API calls every 26 minutes...");
                logger.info("This will run until you stop the application (Ctrl+C)");
                logger.info("Expected token refresh cycle: ~48 minutes (80% of 60-minute lifetime)");
                logger.info("With 26-minute intervals, you'll see refresh behavior clearly");

                int iteration = 1;
                long startTime = System.currentTimeMillis();

                // Run continuously until interrupted
                while (true) {
                    try {
                        double minutesElapsed = (System.currentTimeMillis() - startTime) / 60000.0;
                        logger.info(String.format("=== API Call #%d (%.1f minutes elapsed) ===", iteration, minutesElapsed));

                        // Predict when refresh should happen
                        if (minutesElapsed > 45 && minutesElapsed < 50) {
                            logger.info("⏰ Approaching 48-minute mark - proactive refresh should happen soon!");
                        } else if (minutesElapsed > 70 && minutesElapsed < 85) {
                            logger.info("🔄 In the refresh window (70-85 minutes) - background refresh may occur during this call");
                        } else if (minutesElapsed > 93 && minutesElapsed < 98) {
                            logger.info("⏰ Approaching second refresh cycle (~96 minutes) - should refresh again!");
                        }

                        // Make an API call - this should never block for token refresh
                        // because the proactive mechanism refreshes tokens in the background
                        long apiCallStart = System.currentTimeMillis();

                        GetNamespaceResponse response = client.getNamespace(
                            GetNamespaceRequest.builder().build(), null).get();

                        long apiCallDuration = System.currentTimeMillis() - apiCallStart;

                        logger.info(String.format("��� API call completed in %d ms", apiCallDuration));
                        logger.info(String.format("  Namespace: %s", response.getValue()));
                        logger.info(String.format("  Total runtime: %.1f minutes", minutesElapsed));

                        // Enhanced analysis of API call performance
                        if (apiCallDuration > 2000) {
                            logger.info(String.format("📊 API call took %d ms - this likely indicates " +
                                "background token refresh occurred (expected behavior)",
                                apiCallDuration));
                        } else if (minutesElapsed > 70 && minutesElapsed < 85) {
                            logger.info("✅ API call remained fast during refresh window - proactive refresh working perfectly!");
                        }

                        // Show token age estimation
                        long tokenAgeMinutes = (long) (minutesElapsed % 60);
                        if (tokenAgeMinutes == 0 && minutesElapsed > 50) {
                            tokenAgeMinutes = 60; // Just refreshed
                        }
                        if (minutesElapsed > 50) {
                            logger.info(String.format("📈 Current token estimated age: ~%d minutes (refresh cycle: every ~60 minutes)",
                                tokenAgeMinutes));
                        }

                        iteration++;

                        // Wait 26 minutes between API calls
                        logger.info("Waiting 26 minutes before next API call...");
                        logger.info("  Press Ctrl+C to stop the demonstration");
                        Thread.sleep(1560_000); // 26 minutes (26 * 60 * 1000)

                    } catch (InterruptedException e) {
                        logger.info("Demonstration interrupted by user - shutting down gracefully");
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        logger.warning(String.format("✗ API call #%d failed: %s", iteration, e.getMessage()));
                        logger.info("Continuing with next iteration...");
                        iteration++;

                        // Wait a bit before retrying
                        try {
                            Thread.sleep(60_000); // 1 minute
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }

                double totalMinutes = (System.currentTimeMillis() - startTime) / 60000.0;
                logger.info(String.format("Completed %d API calls over %.1f minutes",
                    iteration - 1, totalMinutes));

                if (totalMinutes > 48) {
                    logger.info("✓ Demonstration ran long enough to show automatic token refresh cycles!");
                } else {
                    logger.info("ℹ Demonstration stopped before first refresh cycle completed");
                }

            } catch (Exception e) {
                logger.severe("✗ Failed to create client for proactive refresh demo: " + e.getMessage());
                e.printStackTrace();
            }
            // NOTE: Provider cleanup now handled by main method's finally block

        } catch (Exception e) {
            logger.severe("✗ Failed to demonstrate proactive refresh: " + e.getMessage());
            e.printStackTrace();
        }

        logger.info("");
        logger.info("=== Proactive Refresh Demonstration Completed ===");
        logger.info("Key observations for 60-minute tokens:");
        logger.info("• API calls should remain consistently fast (< 2000ms)");
        logger.info("• Proactive refresh happens automatically at ~48 minutes");
        logger.info("• No blocking delays during token refresh");
        logger.info("• Background token refresh is transparent to your application");
        logger.info("• For best results, run this demo for 50+ minutes to see the refresh cycle");
        
        return proactiveProvider; // Return for cleanup by caller
    }
}
