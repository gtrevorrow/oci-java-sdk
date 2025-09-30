
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
import com.oracle.bmc.responses.AsyncHandler;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This example demonstrates how to use the
 * WorkloadIdentityFederationAuthenticationDetailProvider
 * to authenticate calls to OCI APIs. It shows the basic usage and how to enable
 * an optional
 * circuit breaker for the federation client.
 *
 * <p>
 * <b>Important: buildAsync() Method Benefits</b><br>
 * This example showcases the buildAsync() method, which provides true async
 * semantics for
 * authentication provider initialization. The method offers several key
 * advantages:
 * <ul>
 * <li>Token pre-fetching during provider initialization (not on first use)</li>
 * <li>Fail-fast behavior - authentication issues discovered early</li>
 * <li>Non-blocking provider creation through CompletableFuture composition</li>
 * <li>Concurrent authentication provider initialization becomes possible</li>
 * <li>Elegant async composition with CompletableFuture chaining</li>
 * <li>Superior performance under concurrent load</li>
 * </ul>
 * The async benefits are achieved through the OCI SDK's HttpClient abstraction,
 * which ensures
 * consistent non-blocking behavior regardless of the underlying HTTP client
 * implementation.
 * </p>
 *
 * <p>
 * This example requires the following command-line arguments:
 * <ol>
 * <li>tokenExchangeUrl: The URL of the token exchange endpoint (e.g., from an
 * Identity Domain).</li>
 * <li>clientCredential: The client credential for basic authentication (e.g.,
 * "client_id:client_secret").</li>
 * <li>regionId: The OCI region ID (e.g., "us-ashburn-1").</li>
 * <li>compartmentId: The OCID of the compartment to query (e.g., your tenancy
 * OCID).</li>
 * </ol>
 * It also requires the `OCI_SUBJECT_TOKEN` environment variable to be set with
 * the subject token.
 */
public class WorkloadIdentityFederationAuthenticationExample {

    private static final Logger logger = Logger
            .getLogger(WorkloadIdentityFederationAuthenticationExample.class.getName());

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

        // Note: this example expects real OCI values. Placeholder endpoints,
        // credentials, or subject tokens
        // will result in 403 Access Denied responses during the token exchange flow.

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
        // This is the basic configuration that relies on SDK defaults for HTTP client
        // settings.
        WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = WorkloadIdentityFederationAuthenticationDetailProvider
                .builder()
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
                logger.log(Level.SEVERE, "Stacktrace:", e);
                logger.info("Continuing with async example despite sync authentication failure...");
            }

            // --- Demonstrate buildAsync() usage ---
            logger.info("");
            logger.info("=== Testing buildAsync() method ===");
            logger.info("Creating authentication provider asynchronously (non-blocking)...");

            // Use array to store reference for cleanup (works around final variable issue)
            final WorkloadIdentityFederationAuthenticationDetailProvider[] asyncProviderRef = new WorkloadIdentityFederationAuthenticationDetailProvider[1];

            try {
                // Demonstrate the TRUE async benefit: non-blocking provider initialization
                // This starts the async initialization but doesn't block the current thread
                long startTime = System.currentTimeMillis();

                logger.info("Starting async provider initialization...");

                // Start the async pipeline directly from buildAsync() and compose further async
                // work
                CompletableFuture<Void> asyncFlow = WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                        .tokenExchangeUrl(tokenExchangeUrl)
                        .subjectTokenSupplier(() -> subjectToken)
                        .clientCredential(clientCredential)
                        .region(Region.fromRegionId(regionId))
                        .secondsToExpireSessionTokenEarly(300L)
                        .buildAsync()
                        .thenCompose(provider -> {
                            long initTime = System.currentTimeMillis() - startTime;
                            logger.info("✓ Async provider ready after " + initTime + "ms (including parallel work)");
                            logger.info("Provider is pre-authenticated - no 'cold start' delay for API calls!");

                            // Store provider reference for cleanup
                            asyncProviderRef[0] = provider;

                            // Create async client and make API call - all non-blocking
                            @SuppressWarnings("resource")
                            final ObjectStorageAsyncClient asyncClient = ObjectStorageAsyncClient.builder()
                                    .build(provider);

                            logger.info("Making API call with pre-authenticated provider (non-blocking)...");

                            // Bridge OCI Future + AsyncHandler to CompletableFuture
                            final CompletableFuture<GetNamespaceResponse> apiCall = new CompletableFuture<>();
                            GetNamespaceRequest request = GetNamespaceRequest.builder().build();
                            asyncClient.getNamespace(
                                    request,
                                    new AsyncHandler<GetNamespaceRequest, GetNamespaceResponse>() {
                                        @Override
                                        public void onSuccess(GetNamespaceRequest req, GetNamespaceResponse resp) {
                                            apiCall.complete(resp);
                                        }

                                        @Override
                                        public void onError(GetNamespaceRequest req, Throwable error) {
                                            apiCall.completeExceptionally(error);
                                        }
                                    });

                            // When the call completes, close the client and return the response future
                            return apiCall.whenComplete((r, t) -> {
                                try {
                                    asyncClient.close();
                                } catch (Exception e) {
                                    logger.warning("Warning during client cleanup: " + e.getMessage());
                                }
                            });
                        })
                        .thenAccept(response -> {
                            long totalTime = System.currentTimeMillis() - startTime;
                            logger.info("✓ Async API call completed in " + totalTime + "ms total");
                            logger.info("Account namespace (via async provider): " + response.getValue());
                            logger.info(
                                    "This demonstrates true async benefits - no blocking, efficient resource usage!");
                        })
                        .exceptionally(throwable -> {
                            logger.severe("✗ Async provider or API call failed: " + throwable.getMessage());
                            return null;
                        });

                // While the provider is initializing asynchronously, we can do other work
                logger.info("Provider initialization started. Current thread is NOT blocked!");
                logger.info("Doing other work while provider initializes in background...");

                // Simulate other work (this could be initializing other components,
                // setting up configurations, etc.)
                for (int i = 1; i <= 3; i++) {
                    Thread.sleep(500); // Simulate 500ms of other work
                    logger.info("  Doing other work... step " + i + "/3");
                }

                // Wait for the async pipeline to complete (provider init + first API call)
                asyncFlow.join();

            } catch (Exception e) {
                logger.severe("✗ Unexpected error in buildAsync example: " + e.getMessage());
                logger.log(Level.SEVERE, "Stacktrace:", e);
            }

            // Store the provider reference for cleanup
            asyncAuthProvider = asyncProviderRef[0];

            logger.info("");
            logger.info("=== Example completed successfully! ===");
            logger.info("Both synchronous and asynchronous authentication providers worked correctly.");

            // Demonstrate the automatic background refresh functionality (async
            // composition)
            // Start the proactive refresh demo asynchronously and compose its first API
            // call
            CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> proactiveFlow = demonstrateProactiveRefreshAsync(
                    tokenExchangeUrl, clientCredential, regionId);

            // Wait for the proactive demo's first API call to complete (join at end of
            // composed flow)
            proactiveProvider = proactiveFlow.join();

            logger.info("");
            logger.info("Proactive refresh demo is now running. Watch for automatic token refresh logs.");
            logger.info("Press Ctrl+C to exit once you've observed the proactive refresh behavior.");

            waitForShutdownSignal();

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

    private static void waitForShutdownSignal() {
        CountDownLatch shutdownLatch = new CountDownLatch(1);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received. Preparing to clean up authentication providers...");
            shutdownLatch.countDown();
        }));

        try {
            shutdownLatch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warning("Shutdown wait interrupted; proceeding with cleanup.");
        }
    }

    /**
     * Asynchronously demonstrates proactive background token refresh: builds the
     * provider with
     * circuit breaker support and a retry configuration (the retry configuration
     * automatically
     * enables proactive refresh), then makes a single async API call using
     * ObjectStorageAsyncClient.
     * Returns the initialized provider for cleanup.
     */
    private static CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> demonstrateProactiveRefreshAsync(
            String tokenExchangeUrl, String clientCredential, String regionId) {
        logger.info("");
        logger.info("=== Demonstrating Proactive Background Token Refresh (Async) ===");
        logger.info(
                "This demonstrates async provider init and a non-blocking API call; proactive refresh will occur later in the background.");

        // Build provider asynchronously with circuit breaker support and retry
        // configuration
        // (retry configuration automatically enables proactive refresh)
        return WorkloadIdentityFederationAuthenticationDetailProvider.builder()
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
                .secondsToExpireSessionTokenEarly(300L)
                .withCircuitBreaker()
                .retryConfiguration(RetryConfiguration.BASIC)
                .buildAsync()
                .thenCompose(provider -> {
                    logger.info("✓ Proactive refresh provider initialized (async)");
                    logger.info("  Proactive refresh will happen automatically before token expiry");

                    // Create async client and perform a single non-blocking API call
                    @SuppressWarnings("resource")
                    final ObjectStorageAsyncClient client = ObjectStorageAsyncClient.builder().build(provider);

                    final CompletableFuture<GetNamespaceResponse> apiCall = new CompletableFuture<>();
                    GetNamespaceRequest request = GetNamespaceRequest.builder().build();
                    client.getNamespace(
                            request,
                            new AsyncHandler<GetNamespaceRequest, GetNamespaceResponse>() {
                                @Override
                                public void onSuccess(GetNamespaceRequest req, GetNamespaceResponse resp) {
                                    apiCall.complete(resp);
                                }

                                @Override
                                public void onError(GetNamespaceRequest req, Throwable error) {
                                    apiCall.completeExceptionally(error);
                                }
                            });

                    return apiCall
                            .whenComplete((r, t) -> {
                                try {
                                    client.close();
                                } catch (Exception e) {
                                    logger.warning("Warning during client cleanup: " + e.getMessage());
                                }
                            })
                            .thenApply(resp -> {
                                logger.info("✓ Proactive demo async API call completed");
                                logger.info("  Namespace: " + resp.getValue());
                                return provider; // return provider for caller to manage lifecycle
                            });
                });
    }
}
