/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth.internal;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.oracle.bmc.auth.SessionKeySupplier;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.http.ClientConfigurator;
import com.oracle.bmc.http.client.Method;
import com.oracle.bmc.http.internal.ClientCall;
import com.oracle.bmc.model.BmcException;
import com.oracle.bmc.requests.BmcRequest;
import com.oracle.bmc.responses.BmcResponse;
import com.oracle.bmc.retrier.RetryConfiguration;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

public class WorkloadIdentityFederationClient extends AbstractAsyncFederationClient {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(WorkloadIdentityFederationClient.class);

    // Proactive refresh configuration
    private static final long MIN_REFRESH_DELAY_SECONDS = 60; // Minimum 1 minute delay
    private static final long PROACTIVE_REFRESH_FAILURE_RETRY_DELAY_SECONDS = 60;

    private final Supplier<String> subjectTokenSupplier;
    private final String clientCredentials;
    private final Long secondsToExpireSessionTokenEarly;

    // Proactive refresh components
    private final ScheduledExecutorService proactiveRefreshScheduler;
    private volatile ScheduledFuture<?> scheduledRefreshTask;

    private final ExecutorService tokenExchangeExecutor;
    private static final AtomicLong TOKEN_EXCHANGE_THREAD_ID = new AtomicLong(0);

    private final RetryConfiguration tokenExchangeRetryConfiguration;

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
                null);
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
            RetryConfiguration tokenExchangeRetryConfiguration) {
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

        this.tokenExchangeRetryConfiguration = tokenExchangeRetryConfiguration;

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

        this.tokenExchangeExecutor = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r,
                    "WorkloadIdentityFederationClient-TokenExchange-" + TOKEN_EXCHANGE_THREAD_ID.incrementAndGet());
            t.setDaemon(true);
            return t;
        });

        LOG.debug(
                "WorkloadIdentityFederationClient initialized with endpoint: {}, proactive refresh enabled: {}, token exchange retry config present: {}",
                tokenExchangeEndpoint,
                enableProactiveRefresh,
                tokenExchangeRetryConfiguration != null);
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
     * Overrides the base implementation to provide proactive token refresh
     * behavior.
     * <p>
     * Unlike the abstract base class which only refreshes tokens when they are
     * already
     * invalid,
     * this implementation refreshes tokens early (before expiration) to prevent
     * authentication failures in workload identity use cases where timing is
     * critical.
     * <p>
     * The early refresh is controlled by secondsToExpireSessionTokenEarly (default
     * 5 minutes),
     * ensuring tokens are renewed well before they expire to avoid any risk of
     * using
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

        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        String subjectToken = subjectTokenSupplier.get();
                        if (subjectToken == null || subjectToken.isEmpty()) {
                            throw new IllegalStateException("Subject token must not be null or empty");
                        }

                        KeyPair keyPair = sessionKeySupplier.getKeyPair();
                        if (keyPair == null) {
                            throw new IllegalStateException("KeyPair must not be null");
                        }
                        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                        if (publicKey == null) {
                            throw new IllegalStateException("Public key must not be null");
                        }

                        String basicAuth = clientCredentials;
                        if (LOG.isDebugEnabled()) {
                            String masked = basicAuth == null
                                    ? "null"
                                    : (basicAuth.length() <= 8
                                            ? "********"
                                            : basicAuth.substring(0, 4)
                                                    + "****"
                                                    + basicAuth.substring(basicAuth.length() - 4));
                            LOG.debug("Basic Auth Header (encoded, masked): {}", masked);
                        }

                        String requestBody = buildTokenExchangeRequestBody(subjectToken, publicKey);

                        TokenExchangeResponseBody tokenResponse = ClientCall.builder(
                                federationClient,
                                new TokenExchangeRequestWrapper(requestBody),
                                TokenExchangeResponseWrapper.Builder::new)
                                .logger(LOG, "WorkloadIdentityFederationClient")
                                .method(Method.POST)
                                .appendHeader("Authorization", "Basic " + basicAuth)
                                .appendHeader("Content-Type", "application/x-www-form-urlencoded")
                                .accept("application/json")
                                .hasBody()
                                .handleBody(
                                        TokenExchangeResponseBody.class,
                                        (w, t) -> w.body = t)
                                .clientConfigurator(null)
                                .circuitBreaker(circuitBreaker)
                                .retryConfiguration(this.tokenExchangeRetryConfiguration)
                                .callSync().body;

                        if (tokenResponse == null || tokenResponse.token == null) {
                            throw new IllegalStateException(
                                    "Token exchange response did not contain 'token'");
                        }

                        return new SecurityTokenAdapter(tokenResponse.token, sessionKeySupplier);
                    } catch (BmcException e) {
                        LOG.error("Token exchange failed", e);
                        throw e;
                    } catch (Exception e) {
                        LOG.error("Unable to exchange token", e);
                        throw new RuntimeException("Unable to exchange token", e);
                    }
                },
                tokenExchangeExecutor);
    }

    private static String buildTokenExchangeRequestBody(String subjectToken, RSAPublicKey publicKey)
            throws java.io.UnsupportedEncodingException {
        StringBuilder requestBodyBuilder = new StringBuilder();
        requestBodyBuilder
                .append("grant_type=")
                .append(
                        java.net.URLEncoder.encode(
                                "urn:ietf:params:oauth:grant-type:token-exchange", "UTF-8"));
        requestBodyBuilder
                .append("&subject_token_type=")
                .append(java.net.URLEncoder.encode("jwt", "UTF-8"));
        requestBodyBuilder
                .append("&subject_token=")
                .append(java.net.URLEncoder.encode(subjectToken, "UTF-8"));
        requestBodyBuilder
                .append("&requested_token_type=")
                .append(java.net.URLEncoder.encode("urn:oci:token-type:oci-upst", "UTF-8"));
        String publicKeyDerBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        requestBodyBuilder
                .append("&public_key=")
                .append(java.net.URLEncoder.encode(publicKeyDerBase64, "UTF-8"));

        return requestBodyBuilder.toString();
    }

    private static final class TokenExchangeRequestWrapper extends BmcRequest<String> {
        private final String requestBody;

        private TokenExchangeRequestWrapper(String requestBody) {
            this.requestBody = requestBody;
        }

        @Override
        public String getBody$() {
            return requestBody;
        }
    }

    private static final class TokenExchangeResponseBody {
        @JsonProperty("token")
        private String token;
    }

    private static final class TokenExchangeResponseWrapper extends BmcResponse {
        private final TokenExchangeResponseBody body;

        private TokenExchangeResponseWrapper(int status, TokenExchangeResponseBody body) {
            super(status);
            this.body = body;
        }

        private static final class Builder implements BmcResponse.Builder<TokenExchangeResponseWrapper> {
            private int status;
            TokenExchangeResponseBody body;

            @Override
            public BmcResponse.Builder<TokenExchangeResponseWrapper> __httpStatusCode__(
                    int __httpStatusCode__) {
                this.status = __httpStatusCode__;
                return this;
            }

            @Override
            public BmcResponse.Builder<TokenExchangeResponseWrapper> headers(
                    java.util.Map<String, java.util.List<String>> headers) {
                return this;
            }

            @Override
            public BmcResponse.Builder<TokenExchangeResponseWrapper> copy(
                    TokenExchangeResponseWrapper o) {
                this.status = o.get__httpStatusCode__();
                this.body = o.body;
                return this;
            }

            @Override
            public TokenExchangeResponseWrapper build() {
                return new TokenExchangeResponseWrapper(status, body);
            }
        }
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
     * Returns the number of seconds from now when a proactive refresh should be
     * scheduled,
     * typically at 80% of the token's remaining lifetime.
     *
     * @return Optional containing seconds until proactive refresh, or empty if no
     *         valid token or scheduling not possible
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

        // Cap the delay to a reasonable maximum (e.g., 1 hour) to handle very
        // long-lived tokens
        refreshDelaySeconds = Math.min(refreshDelaySeconds, 3600);

        LOG.info(
                "Proactive refresh: token valid for ~{}s; targeting refresh in {}s (~80% of lifetime)",
                totalLifetimeSeconds,
                refreshDelaySeconds);

        return Optional.of(refreshDelaySeconds);
    }

    /**
     * Schedules a proactive token refresh based on the current token's expiration
     * time.
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
            LOG.info("Proactive refresh: starting background token refresh");
            refreshAndGetSecurityTokenInnerAsync(true, null, true)
                    .thenRun(() -> {
                        LOG.info("Proactive refresh: token refresh completed successfully");
                        // onTokenRefreshCompleted will be called automatically and schedule the next
                        // refresh
                    })
                    .exceptionally(throwable -> {
                        LOG.warn("Proactive refresh: token refresh failed; scheduling retry", throwable);
                        scheduleRetryAfterProactiveRefreshFailure();
                        return null;
                    });
        } catch (Exception e) {
            LOG.warn("Proactive refresh: failed to initiate token refresh; scheduling retry", e);
            scheduleRetryAfterProactiveRefreshFailure();
        }
    }

    private void scheduleRetryAfterProactiveRefreshFailure() {
        if (proactiveRefreshScheduler == null) {
            return;
        }

        try {
            if (scheduledRefreshTask != null && !scheduledRefreshTask.isDone()) {
                scheduledRefreshTask.cancel(false);
            }
            scheduledRefreshTask = proactiveRefreshScheduler.schedule(
                    this::performProactiveRefresh,
                    PROACTIVE_REFRESH_FAILURE_RETRY_DELAY_SECONDS,
                    TimeUnit.SECONDS);
        } catch (Exception e) {
            LOG.warn("Proactive refresh: failed to schedule retry", e);
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
     * Shuts down the proactive refresh scheduler.
     * This method should be called when the client is no longer needed to clean up
     * resources.
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

        tokenExchangeExecutor.shutdown();
        try {
            if (!tokenExchangeExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                tokenExchangeExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            tokenExchangeExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
