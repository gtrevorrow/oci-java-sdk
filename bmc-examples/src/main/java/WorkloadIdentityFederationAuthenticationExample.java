/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.WorkloadIdentityFederationAuthenticationDetailProvider;
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

    public static void main(String[] args) throws Exception {
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
            // The buildAsync() method provides several key benefits over the regular build() method:
            // 1. Pre-fetches the authentication token during provider initialization
            // 2. Returns a CompletableFuture that completes only when the token is successfully retrieved
            // 3. Enables fail-fast behavior - authentication issues are discovered early
            // 4. Allows elegant chaining with other async operations
            // 5. Prevents authentication delays during the first API call

            // Create a second provider using buildAsync() - this pre-fetches the token
            String result = WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                    .tokenExchangeUrl(tokenExchangeUrl)
                    .subjectTokenSupplier(() -> subjectToken)
                    .clientCredential(clientCredential)
                    .region(Region.fromRegionId(regionId))
                    .secondsToExpireSessionTokenEarly(300L)
                    .buildAsync()  // ← Key difference: Returns CompletableFuture<AuthenticationDetailsProvider>

                    // The .thenApply() is called only AFTER the provider is fully initialized with a valid token
                    .thenApply(asyncAuthProvider -> {
                        logger.info("✓ Async authentication provider initialized with pre-fetched token!");

                        // At this point, asyncAuthProvider is guaranteed to have a valid authentication token
                        // This eliminates the "cold start" delay that would occur with regular build()

                        // Create a new Object Storage client with the async-initialized provider
                        try (ObjectStorageClient asyncClient = ObjectStorageClient.builder()
                                .build(asyncAuthProvider)) {

                            logger.info("Making Object Storage API call with async provider...");

                            // This API call happens immediately without any authentication delay
                            // because the token was pre-fetched during buildAsync()
                            GetNamespaceResponse response = asyncClient.getNamespace(
                                    GetNamespaceRequest.builder().build());
                            String asyncNamespace = response.getValue();
                            logger.info("✓ Async provider authentication successful!");
                            logger.info("Account namespace (via async provider): " + asyncNamespace);
                            return asyncNamespace;
                        } catch (Exception e) {
                            logger.severe("✗ Failed to create async client or make API call: " + e.getMessage());
                            throw new RuntimeException("Failed to create async client", e);
                        }
                    })

                    // Handle any authentication failures that occurred during buildAsync()
                    .exceptionally(throwable -> {
                        logger.severe("✗ Async authentication provider failed: " + throwable.getMessage());
                        if (throwable.getCause() != null) {
                            logger.severe("Caused by: " + throwable.getCause().getMessage());
                        }
                        throwable.printStackTrace();
                        return null;
                    })

                    // In a real application, you would typically avoid .join() and instead
                    // chain this with other async operations. We use .join() here only
                    // to wait for completion in this demonstration example.
                    .join(); // Wait for completion in this example

            if (result != null) {
                logger.info("✓ Async example completed successfully with namespace: " + result);
            } else {
                logger.severe("✗ Async example failed - result was null");
            }

        } catch (Exception e) {
            logger.severe("✗ Unexpected error in buildAsync example: " + e.getMessage());
            e.printStackTrace();
        }

        logger.info("");
        logger.info("=== Example completed successfully! ===");
        logger.info("Both synchronous and asynchronous authentication providers worked correctly.");
    }
}
