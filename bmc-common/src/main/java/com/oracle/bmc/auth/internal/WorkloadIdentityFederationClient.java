/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth.internal;

import com.oracle.bmc.auth.SessionKeySupplier;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.http.ClientConfigurator;
import com.oracle.bmc.http.client.Method;
import com.oracle.bmc.http.client.Serializer;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class WorkloadIdentityFederationClient extends AbstractAsyncFederationClient {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(WorkloadIdentityFederationClient.class);

    // Proactive refresh configuration
    private static final long MIN_REFRESH_DELAY_SECONDS = 60; // Minimum 1 minute delay

    private final Supplier<String> subjectTokenSupplier;
    private final String clientCredentials;
    private final Long secondsToExpireSessionTokenEarly;

    // Proactive refresh components
    private final ScheduledExecutorService proactiveRefreshScheduler;
    private volatile ScheduledFuture<?> scheduledRefreshTask;

    // Retry configuration - configurable via setters
    private volatile boolean enableRetryOnFailure; // Default: no retries
    private volatile int maxRetryAttempts; // Default: 3 attempts if enabled
    private volatile long retryDelaySeconds; // Default: 30 seconds between retries
    private final AtomicInteger currentRetryCount = new AtomicInteger(); // Track current retry attempts

    public WorkloadIdentityFederationClient(
            String tokenExchangeEndpoint,
            Supplier<String> subjectTokenSupplier,
            SessionKeySupplier sessionKeySupplier,
            String clientCredentials,
            ClientConfigurator clientConfigurator,
            CircuitBreakerConfiguration circuitBreakerConfiguration,
            List<ClientConfigurator> additionalClientConfigurators,
            Long secondsToExpireSessionTokenEarly,
            boolean enableProactiveRefresh) {
        this(
                tokenExchangeEndpoint,
                subjectTokenSupplier,
                sessionKeySupplier,
                clientCredentials,
                clientConfigurator,
                circuitBreakerConfiguration,
                additionalClientConfigurators,
                secondsToExpireSessionTokenEarly,
                enableProactiveRefresh,
                false, // enableRetryOnFailure
                3,     // maxRetryAttempts
                30L);  // retryDelaySeconds
    }

    public WorkloadIdentityFederationClient(
            String tokenExchangeEndpoint,
            Supplier<String> subjectTokenSupplier,
            SessionKeySupplier sessionKeySupplier,
            String clientCredentials,
            ClientConfigurator clientConfigurator,
            CircuitBreakerConfiguration circuitBreakerConfiguration,
            List<ClientConfigurator> additionalClientConfigurators,
            Long secondsToExpireSessionTokenEarly,
            boolean enableProactiveRefresh,
            boolean enableRetryOnFailure,
            int maxRetryAttempts,
            long retryDelaySeconds) {
        super(
                sessionKeySupplier,
                tokenExchangeEndpoint,
                clientConfigurator,
                circuitBreakerConfiguration,
                additionalClientConfigurators);
        this.subjectTokenSupplier = subjectTokenSupplier;
        this.clientCredentials = clientCredentials;
        this.secondsToExpireSessionTokenEarly = secondsToExpireSessionTokenEarly != null
                ? secondsToExpireSessionTokenEarly
                : 300L;

        // Set retry configuration from constructor parameters
        this.enableRetryOnFailure = enableRetryOnFailure;
        this.maxRetryAttempts = maxRetryAttempts;
        this.retryDelaySeconds = retryDelaySeconds;
        this.currentRetryCount.set(0);

        // Only initialize proactive refresh scheduler if explicitly enabled
        if (enableProactiveRefresh) {
            this.proactiveRefreshScheduler = new ScheduledThreadPoolExecutor(1, r -> {
                Thread t = new Thread(r, "WorkloadIdentityFederationClient-ProactiveRefresh");
                t.setDaemon(true);
                return t;
            });
            LOG.debug("Proactive refresh enabled - scheduler initialized");
        } else {
            this.proactiveRefreshScheduler = null;
            LOG.debug("Proactive refresh disabled - no scheduler created");
        }

        LOG.debug(
                "WorkloadIdentityFederationClient initialized with endpoint: {}, retry enabled: {}, max attempts: {}, delay: {}s",
                tokenExchangeEndpoint, enableRetryOnFailure, maxRetryAttempts, retryDelaySeconds);
    }

    public WorkloadIdentityFederationClient(
            String tokenExchangeEndpoint,
            Supplier<String> subjectTokenSupplier,
            SessionKeySupplier sessionKeySupplier,
            String clientCredentials) {
        this(
                tokenExchangeEndpoint,
                subjectTokenSupplier,
                sessionKeySupplier,
                clientCredentials,
                null,
                null,
                Collections.emptyList(),
                null,
                false);
    }


    /**
     * Overrides the base implementation to provide proactive token refresh behavior.
     * <p>
     * Unlike the base class which only refreshes tokens when they are already invalid,
     * this implementation refreshes tokens early (before expiration) to prevent
     * authentication failures in workload identity scenarios where timing is critical.
     * <p>
     * The early refresh is controlled by secondsToExpireSessionTokenEarly (default 5 minutes),
     * ensuring tokens are renewed well before they expire to avoid any risk of using
     * an expired token during authentication.
     *
     * @return CompletableFuture containing the security token
     */
    @Override
    public CompletableFuture<String> getSecurityToken() {
        return refreshAndGetSecurityTokenIfExpiringWithin(
                Duration.ofSeconds(secondsToExpireSessionTokenEarly));
    }

    @Override
    protected CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer() {
        LOG.info("getSecurityTokenFromServer called, getting session token from Identity Domain");

        try {
            String subjectToken = subjectTokenSupplier.get();
            if (subjectToken == null || subjectToken.isEmpty()) {
                LOG.error("Subject token is null or empty, cannot proceed with token exchange.");
                CompletableFuture<SecurityTokenAdapter> future = new CompletableFuture<>();
                future.completeExceptionally(
                        new IllegalStateException("Subject token must not be null or empty"));
                return future;
            }

            KeyPair keyPair = sessionKeySupplier.getKeyPair();
            if (keyPair == null) {
                LOG.error("KeyPair is null, cannot proceed with token exchange.");
                CompletableFuture<SecurityTokenAdapter> future = new CompletableFuture<>();
                future.completeExceptionally(new IllegalStateException("KeyPair must not be null"));
                return future;
            }
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            if (publicKey == null) {
                LOG.error("Public key is null, cannot proceed with token exchange.");
                CompletableFuture<SecurityTokenAdapter> future = new CompletableFuture<>();
                future.completeExceptionally(
                        new IllegalStateException("Public key must not be null"));
                return future;
            }

            String basicAuth = clientCredentials;
            // Avoid logging full credentials; mask for safety
            if (LOG.isDebugEnabled()) {
                String masked = basicAuth == null ? "null" : (basicAuth.length() <= 8 ? "********" : basicAuth.substring(0, 4) + "****" + basicAuth.substring(basicAuth.length() - 4));
                LOG.debug("Basic Auth Header (encoded, masked): {}", masked);
            }

            StringBuilder requestBodyBuilder = new StringBuilder();
            requestBodyBuilder
                    .append("grant_type=")
                    .append(
                            java.net.URLEncoder.encode(
                                    "urn:ietf:params:oauth:grant-type:token-exchange",
                                    "UTF-8"));
            requestBodyBuilder
                    .append("&subject_token_type=")
                    .append(java.net.URLEncoder.encode("jwt", "UTF-8"));
            requestBodyBuilder
                    .append("&subject_token=")
                    .append(java.net.URLEncoder.encode(subjectToken, "UTF-8"));
            requestBodyBuilder
                    .append("&requested_token_type=")
                    .append(java.net.URLEncoder.encode("urn:oci:token-type:oci-upst", "UTF-8"));
            String publicKeyDerBase64 = java.util.Base64.getEncoder()
                    .encodeToString(publicKey.getEncoded());
            requestBodyBuilder
                    .append("&public_key=")
                    .append(java.net.URLEncoder.encode(publicKeyDerBase64, "UTF-8"));

            String requestBody = requestBodyBuilder.toString();

            return federationClient
                    .createRequest(Method.POST)
                    .header("Authorization", "Basic " + basicAuth)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(requestBody)
                    .execute()
                    .toCompletableFuture()
                    .thenCompose(
                            response -> {
                                if (response.status() != 200) {
                                    return response.textBody()
                                            .thenCompose(
                                                    body -> {
                                                        LOG.error(
                                                                "Token exchange request failed with status: {} and body: {}",
                                                                response.status(),
                                                                body);
                                                        response.close();
                                                        CompletableFuture<SecurityTokenAdapter> failed = new CompletableFuture<>();
                                                        failed.completeExceptionally(
                                                                new RuntimeException(
                                                                        "Token exchange request failed with status: "
                                                                                + response
                                                                                .status()));
                                                        return failed;
                                                    });
                                }
                                return response.textBody()
                                        .thenApply(
                                                body -> {
                                                    try {
                                                        @SuppressWarnings("unchecked")
                                                        Map<String, Object> responseMap = Serializer
                                                                .getDefault()
                                                                .readValue(
                                                                        body,
                                                                        Map.class);
                                                        Object accessTokenObj = responseMap
                                                                .get("token");
                                                        String accessToken = accessTokenObj != null
                                                                ? accessTokenObj.toString()
                                                                : null;
                                                        LOG.debug(
                                                                "Token exchange response: {}",
                                                                body);
                                                        return new SecurityTokenAdapter(
                                                                accessToken,
                                                                sessionKeySupplier);
                                                    } catch (java.io.IOException e) {
                                                        throw new RuntimeException(
                                                                "Failed to parse token exchange response",
                                                                e);
                                                    }
                                                })
                                        .whenComplete((r, t) -> response.close());
                            });
        } catch (Exception e) {
            LOG.error("Unable to exchange token", e);
            CompletableFuture<SecurityTokenAdapter> future = new CompletableFuture<>();
            future.completeExceptionally(new RuntimeException("Unable to exchange token", e));
            return future;
        }
    }

    @Override
    public CompletableFuture<String> refreshAndGetSecurityToken() {
        // Delegate to the parent's coordinated refresh logic
        return refreshAndGetSecurityTokenInnerAsync(true, null, true);
    }

    @Override
    public String getStringClaim(String key) {
        return securityTokenAdapter.getStringClaim(key);
    }

    @Override
    protected void onTokenRefreshCompleted(Duration tokenValidDuration) {
        LOG.debug("Token refresh completed, token valid for: {}", tokenValidDuration);
        // Only schedule proactive refresh if scheduler is enabled
        if (proactiveRefreshScheduler != null) {
            LOG.debug("Token refresh completed, scheduling proactive refresh");
            scheduleProactiveTokenRefresh();
        } else {
            LOG.debug("Token refresh completed, proactive refresh disabled");
        }
    }

    /**
     * Calculates when the next proactive token refresh should occur.
     * Returns the number of seconds from now when a proactive refresh should be scheduled,
     * typically at 80% of the token's remaining lifetime.
     *
     * @return Optional containing seconds until proactive refresh, or empty if no valid token or scheduling not possible
     */
    private Optional<Long> calculateSecondsUntilProactiveRefresh() {
        // Check if we have a valid token
        if (!securityTokenAdapter.isValid()) {
            // Token is invalid/expired, should refresh immediately
            LOG.info("Proactive refresh: token invalid/expired; scheduling immediate refresh");
            return Optional.of(0L);
        }

        Duration tokenValidDuration = securityTokenAdapter.getTokenValidDuration();
        if (tokenValidDuration == null) {
            LOG.warn("Proactive refresh: token valid duration unknown; cannot schedule proactively");
            return Optional.empty();
        }

        long totalLifetimeSeconds = tokenValidDuration.getSeconds();
        long refreshDelaySeconds = Math.max((long) (totalLifetimeSeconds * 0.8), MIN_REFRESH_DELAY_SECONDS);

        // Cap the delay to a reasonable maximum (e.g., 1 hour) to handle very long-lived tokens
        refreshDelaySeconds = Math.min(refreshDelaySeconds, 3600);

        LOG.info(
                "Proactive refresh: token valid for ~{}s; targeting refresh in {}s (~80% of lifetime)",
                totalLifetimeSeconds,
                refreshDelaySeconds);

        return Optional.of(refreshDelaySeconds);
    }

    /**
     * Schedules a proactive token refresh based on the current token's expiration time.
     * This method cancels any previously scheduled refresh and schedules a new one
     * using the federation client's calculation of when to refresh proactively.
     */
    private void scheduleProactiveTokenRefresh() {
        // Only schedule if proactive refresh is enabled
        if (proactiveRefreshScheduler == null) {
            LOG.debug("Proactive refresh disabled, skipping scheduling");
            return;
        }

        try {
            // Cancel any existing scheduled refresh
            if (scheduledRefreshTask != null && !scheduledRefreshTask.isDone()) {
                scheduledRefreshTask.cancel(false);
                LOG.debug("Cancelled previous proactive refresh task");
            }

            // Get the recommended delay from the federation client
            Optional<Long> secondsUntilRefresh = calculateSecondsUntilProactiveRefresh();
            if (!secondsUntilRefresh.isPresent()) {
                LOG.warn("Cannot schedule proactive refresh: could not determine refresh timing");
                return;
            }

            long refreshDelaySeconds = secondsUntilRefresh.get();

            if (refreshDelaySeconds <= 0) {
                LOG.warn("Proactive refresh: scheduling immediate refresh (delay={}s)", refreshDelaySeconds);
                scheduleImmediateRefresh();
                return;
            }

            Instant scheduledAt = Instant.now().plusSeconds(refreshDelaySeconds);
            LOG.info("Proactive refresh: scheduling background refresh in {}s at {}", refreshDelaySeconds, scheduledAt);

            // Schedule the proactive refresh
            scheduledRefreshTask = proactiveRefreshScheduler.schedule(
                    this::performProactiveRefresh,
                    refreshDelaySeconds,
                    TimeUnit.SECONDS);

        } catch (Exception e) {
            LOG.warn("Failed to schedule proactive token refresh", e);
        }
    }

    /**
     * Performs the actual proactive token refresh in the background.
     * This method is called by the scheduled executor service.
     */
    private void performProactiveRefresh() {
        try {
            int attempt = currentRetryCount.get() + 1;
            LOG.info("Proactive refresh: starting background token refresh (attempt {} of {})", attempt, maxRetryAttempts);
            refreshAndGetSecurityTokenInnerAsync(true, null, true)
                    .thenRun(() -> {
                        LOG.info("Proactive refresh: token refresh completed successfully");
                        currentRetryCount.set(0); // Reset retry counter on success
                        // onTokenRefreshCompleted will be called automatically and schedule the next refresh
                    })
                    .exceptionally(throwable -> {
                        LOG.warn("Proactive refresh: token refresh failed (attempt {}), scheduling retry if enabled", attempt, throwable);
                        scheduleRetryRefresh();
                        return null;
                    });
        } catch (Exception e) {
            LOG.warn("Proactive refresh: failed to initiate token refresh, scheduling retry if enabled", e);
            scheduleRetryRefresh();
        }
    }

    /**
     * Schedules an immediate refresh when the token is already expired.
     */
    private void scheduleImmediateRefresh() {
        if (proactiveRefreshScheduler != null) {
            scheduledRefreshTask = proactiveRefreshScheduler.schedule(
                    this::performProactiveRefresh,
                    0,
                    TimeUnit.SECONDS);
        }
    }

    /**
     * Schedules a retry refresh with a short delay when proactive refresh fails.
     * Only retries if enableRetryOnFailure is true and within maxRetryAttempts limit.
     */
    private void scheduleRetryRefresh() {
        // Check if retries are enabled
        if (!enableRetryOnFailure) {
            LOG.warn("Proactive refresh: refresh failed and retries are disabled; skipping retry");
            currentRetryCount.set(0); // Reset for future refresh cycles
            return;
        }

        // Check if we've exceeded max retry attempts
        if (currentRetryCount.get() >= maxRetryAttempts) {
            LOG.warn("Proactive refresh: max retry attempts ({}) exceeded; stopping retries", maxRetryAttempts);
            currentRetryCount.set(0); // Reset for future refresh cycles
            return;
        }

        if (proactiveRefreshScheduler != null) {
            long retryDelay = retryDelaySeconds;

            // Exponential backoff: double the delay for each retry attempt
            for (int i = 0; i < currentRetryCount.get(); i++) {
                retryDelay = Math.min(retryDelay * 2, 3600); // Cap at 1 hour
            }

            LOG.info("Proactive refresh: scheduling retry in {}s (attempt {}/{})",
                retryDelay, currentRetryCount.get() + 1, maxRetryAttempts);

            scheduledRefreshTask = proactiveRefreshScheduler.schedule(
                    this::performProactiveRefresh,
                    retryDelay,
                    TimeUnit.SECONDS);

            // Increment the retry count for next failure
            currentRetryCount.incrementAndGet();
        }
    }

    /**
     * Shuts down the proactive refresh scheduler.
     * This method should be called when the client is no longer needed to clean up resources.
     */
    public void shutdown() {
        if (scheduledRefreshTask != null && !scheduledRefreshTask.isDone()) {
            scheduledRefreshTask.cancel(false);
        }
        if (proactiveRefreshScheduler != null) {
            proactiveRefreshScheduler.shutdown();
            try {
                if (!proactiveRefreshScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    proactiveRefreshScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                proactiveRefreshScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            LOG.debug("Proactive refresh scheduler shut down");
        } else {
            LOG.debug("No proactive refresh scheduler to shut down");
        }
    }
}
