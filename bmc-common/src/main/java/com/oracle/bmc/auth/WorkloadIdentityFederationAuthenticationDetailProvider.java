/// Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
/// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
package com.oracle.bmc.auth;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.io.ByteArrayInputStream;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AuthUtils;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.WorkloadIdentityFederationClient;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;

import org.slf4j.Logger;
/**
 * An {@link BasicAuthenticationDetailsProvider} implementation that uses workload identity federation
 * to authenticate with Oracle Cloud Infrastructure. This provider exchanges a subject token
 * (e.g., a Kubernetes service account token) for an OCI session token, which is then used to
 * sign API requests.
 *
 * <p>
 * This provider offers two key features for robust authentication in long-running applications:
 * <ol>
 * <li><b>Asynchronous Initialization with {@code buildAsync()}:</b><br>
 *    The {@link #builder()} provides a {@code buildAsync()} method that pre-fetches the first
 *    authentication token upon initialization. This "fail-fast" approach ensures that
 *    authentication issues are discovered at startup rather than during the first API call,
 *    and it eliminates the initial authentication delay.</li>
 *
 * <li><b>Automatic Proactive Token Refresh with {@code retryConfiguration()}:</b><br>
 *    For applications that make continuous API calls, this provider offers automatic proactive
 *    token refresh when retry configuration is provided via {@link WorkloadIdentityFederationAuthenticationDetailProviderBuilder#retryConfiguration(RetryConfiguration)}.
 *    When retry configuration is set, the provider uses a background thread to automatically refresh the session token before it
 *    expires, preventing the calling thread from being blocked by token refresh operations and
 *    ensuring consistent API call performance. When no retry configuration is provided, proactive refresh
 *    is disabled to conserve resources.</li>
 * </ol>
 *
 * <p>
 * When proactive refresh is enabled (via retry configuration), it is crucial to call {@link #shutdown()} when the provider
 * is no longer needed to release the background scheduling thread.
 *
 * @see WorkloadIdentityFederationAuthenticationDetailProviderBuilder
 */
@AuthCachingPolicy(cacheKeyId = false, cachePrivateKey = false)
public class WorkloadIdentityFederationAuthenticationDetailProvider
        implements BasicAuthenticationDetailsProvider, RegionProvider, RefreshableOnNotAuthenticatedProvider<String>,
        ProvidesConfigurableRefresh {

    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(WorkloadIdentityFederationAuthenticationDetailProvider.class);

    private final AsyncFederationClient federationClient;
    private final SessionKeySupplier sessionKeySupplier;
    private final Region region;

    public WorkloadIdentityFederationAuthenticationDetailProvider(AsyncFederationClient federationClient,
            SessionKeySupplier sessionKeySupplier, String tokenExchangeUrl,
            Region region) {
        if (federationClient == null) {
            throw new IllegalArgumentException("Federation client must not be null");
        }
        if (tokenExchangeUrl == null || tokenExchangeUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Token exchange URL must not be null or empty");
        }
        if (sessionKeySupplier == null) {
            throw new IllegalArgumentException("Session key supplier must not be null");
        }
        if (region == null) {
            throw new IllegalArgumentException("Region must not be null");
        }

        this.federationClient = federationClient;
        this.sessionKeySupplier = sessionKeySupplier;
        this.region = region;
    }

    public static WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder() {
        return new WorkloadIdentityFederationAuthenticationDetailProviderBuilder();
    }

    /**
     * Builder for {@link WorkloadIdentityFederationAuthenticationDetailProvider}.
     *
     * <p>
     * <b>Required Setters:</b>
     * <ul>
     * <li>{@link #tokenExchangeUrl(String)}</li>
     * <li>{@link #subjectTokenSupplier(Supplier)}</li>
     * <li>{@link #clientCredential(String)}</li>
     * <li>{@link #region(Region)}</li>
     * </ul>
     *
     * <p>
     * <b>Optional Setters:</b>
     * <ul>
     * <li>{@link #secondsToExpireSessionTokenEarly(Long)}</li>
     * <li>{@link #withCircuitBreaker()}</li>
     * <li>{@link #retryConfiguration(RetryConfiguration)}</li>
     * </ul>
     */
    public static class WorkloadIdentityFederationAuthenticationDetailProviderBuilder {

        private String tokenExchangeUrl;
        private Region region;
        private SessionKeySupplier sessionKeySupplier;
        private AsyncFederationClient federationClient;
        private Supplier<String> subjectTokenSupplier;
        private String clientCredential;
        private Long secondsToExpireSessionTokenEarly; // Default to 5 minutes early expiration
        private boolean withCircuitBreaker = false;
        private RetryConfiguration retryConfiguration = null;


        private static final Logger LOG = org.slf4j.LoggerFactory
                .getLogger(WorkloadIdentityFederationAuthenticationDetailProviderBuilder.class);

        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
        }

        /**
         * Creates a new AsyncFederationClient instance.
         *
         * @param sessionKeySupplier the session key supplier to use
         * @return a new AsyncFederationClient instance
         */
        protected AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
            if (this.federationClient == null) {
                CircuitBreakerConfiguration circuitBreakerConfig = null;
                if (withCircuitBreaker) {
                    LOG.debug("Enabling default circuit breaker for federation client.");
                    circuitBreakerConfig = CircuitBreakerConfiguration.builder().build();
                }

                // Proactive refresh is automatically enabled when retry configuration is provided
                boolean enableProactiveRefresh = retryConfiguration != null;
                boolean enableRetry = retryConfiguration != null && retryConfiguration.isEnableRetryOnFailure();
                int maxAttempts = retryConfiguration != null ? retryConfiguration.getMaxRetryAttempts() : 0;
                long delaySeconds = retryConfiguration != null ? retryConfiguration.getRetryDelaySeconds() : 30;

                this.federationClient = new WorkloadIdentityFederationClient(
                        tokenExchangeUrl,
                        subjectTokenSupplier,
                        sessionKeySupplier,
                        clientCredential,
                        null, // No custom client configurator
                        circuitBreakerConfig,
                        Collections.emptyList(), // No additional client configurators
                        secondsToExpireSessionTokenEarly,
                        enableProactiveRefresh, // Automatically enabled when retry config is provided
                        enableRetry,   // Pass retry configuration (false if no config provided)
                        maxAttempts,
                        delaySeconds);
                LOG.debug(
                        "WorkloadIdentityFederationClient created with early expiration: {} seconds, proactive refresh: {}, retry config: {}",
                        this.secondsToExpireSessionTokenEarly, enableProactiveRefresh,
                        retryConfiguration != null ? retryConfiguration : "none (proactive refresh disabled)");
            }
            return this.federationClient;
        }

        /**
         * Sets the client credential (required).
         * If not already Base64 encoded, it will be encoded.
         *
         * @param clientCredential the client credential string.
         * @return this builder.
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder clientCredential(String clientCredential) {
            if (clientCredential == null || clientCredential.trim().isEmpty()) {
                throw new IllegalArgumentException("Client credential must not be null or empty");
            }
            if (!isBase64Encoded(clientCredential)) {
                this.clientCredential = base64Encode(clientCredential);
                LOG.debug("Client Credential (base64 encoded): {}", this.clientCredential);
            } else {
                this.clientCredential = clientCredential;
                LOG.debug("Client Credential (already base64 encoded): {}", this.clientCredential);
            }
            return this;
        }

        private static boolean isBase64Encoded(String str) {
            try {
                Base64.getDecoder().decode(str);
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        private static String base64Encode(String str) {
            return Base64.getEncoder().encodeToString(str.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        /**
         * Sets the number of seconds before the session token expires to consider it
         * expired (optional).
         *
         * @param seconds The number of seconds.
         * @return this builder.
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder secondsToExpireSessionTokenEarly(
                Long seconds) {
            this.secondsToExpireSessionTokenEarly = seconds;
            return this;
        }

        /**
         * Sets the token exchange URL (required).
         *
         * @param tokenExchangeUrl The URL for token exchange.
         * @return this builder.
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder tokenExchangeUrl(String tokenExchangeUrl) {
            if (tokenExchangeUrl == null || tokenExchangeUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("Token exchange URL must not be null or empty");
            }
            this.tokenExchangeUrl = tokenExchangeUrl;
            return this;
        }

        /**
         * Sets the subject token supplier (required).
         *
         * @param subjectTokenSupplier The supplier for the subject token.
         * @return this builder.
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder subjectTokenSupplier(
                Supplier<String> subjectTokenSupplier) {
            if (subjectTokenSupplier == null) {
                throw new IllegalArgumentException("Subject token supplier must not be null");
            }
            this.subjectTokenSupplier = subjectTokenSupplier;
            return this;
        }

        /**
         * Sets the region (required).
         *
         * @param region The region.
         * @return this builder.
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder region(Region region) {
            if (region == null) {
                throw new IllegalArgumentException("Region must not be null");
            }
            this.region = region;
            return this;
        }

        /**
         * Enables a default circuit breaker for the federation client.
         *
         * @return this builder
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder withCircuitBreaker() {
            this.withCircuitBreaker = true;
            return this;
        }

        /**
         * Sets the retry configuration for proactive refresh failures.
         * <p>
         * This method replaces the previous individual retry configuration methods
         * ({@code enableRetryOnFailure()}, {@code maxRetryAttempts()}, {@code retryDelaySeconds()})
         * with a single configuration object approach.
         * </p>
         * <p>
         * <b>Usage Examples:</b>
         * <pre>{@code
         * // Disable retries (default)
         * .retryConfiguration(RetryConfiguration.disabled())
         *
         * // Enable basic retries (3 attempts, 30s delay)
         * .retryConfiguration(RetryConfiguration.basic())
         *
         * // Conservative retries (3 attempts, 60s delay)
         * .retryConfiguration(RetryConfiguration.conservative())
         *
         * // Aggressive retries (5 attempts, 30s delay)
         * .retryConfiguration(RetryConfiguration.aggressive())
         *
         * // Custom configuration
         * .retryConfiguration(RetryConfiguration.custom(10, 120))
         * }</pre>
         *
         * @param retryConfiguration the retry configuration to use
         * @return this builder
         */
        public WorkloadIdentityFederationAuthenticationDetailProviderBuilder retryConfiguration(RetryConfiguration retryConfiguration) {
            if (retryConfiguration == null) {
                throw new IllegalArgumentException("Retry configuration must not be null");
            }
            this.retryConfiguration = retryConfiguration;
            return this;
        }

        /**
         * Builds the {@link WorkloadIdentityFederationAuthenticationDetailProvider}.
         * All required fields must be set before calling this method.
         *
         * @throws IllegalArgumentException if any required field is not set.
         * @return a new instance of
         *         {@link WorkloadIdentityFederationAuthenticationDetailProvider}.
         */
        public WorkloadIdentityFederationAuthenticationDetailProvider build() {
            if (tokenExchangeUrl == null || tokenExchangeUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("Token exchange URL must not be null or empty");
            }
            if (subjectTokenSupplier == null) {
                throw new IllegalArgumentException("Subject token supplier must not be null");
            }
            if (clientCredential == null || clientCredential.trim().isEmpty()) {
                throw new IllegalArgumentException("Client credential must not be null or empty");
            }
            if (region == null) {
                throw new IllegalArgumentException("Region must not be null");
            }

            SessionKeySupplier sessionKeySupplierToUse = sessionKeySupplier != null ? sessionKeySupplier
                    : new SessionKeySupplierImpl();
            this.sessionKeySupplier = new CachingSessionKeySupplier(sessionKeySupplierToUse);
            this.federationClient = createFederationClient(sessionKeySupplierToUse);

            return new WorkloadIdentityFederationAuthenticationDetailProvider(this.federationClient,
                    this.sessionKeySupplier,
                    this.tokenExchangeUrl,
                    region);
        }

        /**
         * Builds the {@link WorkloadIdentityFederationAuthenticationDetailProvider} asynchronously.
         * This method initializes the federation client and pre-fetches the first token,
         * then returns a CompletableFuture that completes with the fully initialized provider.
         *
         * This is useful when you want to ensure the provider is ready with a valid token
         * before passing it to a client that needs authentication.
         *
         * @throws IllegalArgumentException if any required field is not set.
         * @return a CompletableFuture containing the initialized authentication provider
         */
        public CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> buildAsync() {
            if (tokenExchangeUrl == null || tokenExchangeUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("Token exchange URL must not be null or empty");
            }
            if (subjectTokenSupplier == null) {
                throw new IllegalArgumentException("Subject token supplier must not be null");
            }
            if (clientCredential == null || clientCredential.trim().isEmpty()) {
                throw new IllegalArgumentException("Client credential must not be null or empty");
            }
            if (region == null) {
                throw new IllegalArgumentException("Region must not be null");
            }

            SessionKeySupplier sessionKeySupplierToUse = sessionKeySupplier != null ? sessionKeySupplier
                    : new SessionKeySupplierImpl();
            this.sessionKeySupplier = new CachingSessionKeySupplier(sessionKeySupplierToUse);
            this.federationClient = createFederationClient(sessionKeySupplierToUse);

            WorkloadIdentityFederationAuthenticationDetailProvider provider =
                new WorkloadIdentityFederationAuthenticationDetailProvider(this.federationClient,
                        this.sessionKeySupplier,
                        this.tokenExchangeUrl,
                        region);

            // Pre-fetch the first token to ensure the provider is ready
            return provider.federationClient.getSecurityToken()
                .thenApply(token -> {
                    LOG.debug("Authentication provider initialized with token: {}",
                        token != null ? "***" : "null");
                    return provider;
                });
        }


    }

    @Override
    public String refresh() {
        try {
            return federationClient.refreshAndGetSecurityToken().get();
        } catch (Exception e) {
            throw new RuntimeException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage(), e);
        }
    }

    @Override
    public String refreshAndGetSecurityTokenIfExpiringWithin(Duration duration) {
        try {
            return ((ProvidesConfigurableRefresh) federationClient)
                    .refreshAndGetSecurityTokenIfExpiringWithin(duration);
        } catch (Exception e) {
            throw new RuntimeException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage(), e);
        }
    }

    @Override
    public String refreshAndGetSecurityTokenIfExpiringWithin(Duration duration, boolean refreshKeys) {
        try {
            return ((ProvidesConfigurableRefresh) federationClient)
                    .refreshAndGetSecurityTokenIfExpiringWithin(duration, refreshKeys);
        } catch (Exception e) {
            throw new RuntimeException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage(), e);
        }
    }

    @Override
    public Region getRegion() {
        return region;
    }

    @Override
    public String getKeyId() {
        return "ST$" + federationClient.getSecurityToken().join();
    }

    @Override
    public InputStream getPrivateKey() {
        if (sessionKeySupplier instanceof CachingSessionKeySupplier) {
            return new ByteArrayInputStream(((CachingSessionKeySupplier) sessionKeySupplier).getPrivateKeyBytes());
        } else {
            return new ByteArrayInputStream(
                    AuthUtils.toByteArrayFromRSAPrivateKey((RSAPrivateKey) sessionKeySupplier.getKeyPair().getPrivate()));
        }
    }

    @Override
    public String getPassPhrase() {
        return null; // Not applicable for token exchange
    }

    @Override
    public char[] getPassphraseCharacters() {
        return null; // Not applicable for token exchange
    }

    /**
     * Shuts down the authentication provider and releases resources.
     * This method delegates to the federation client's shutdown method to ensure
     * proper cleanup of the proactive refresh scheduler.
     */
    public void shutdown() {
        if (federationClient instanceof WorkloadIdentityFederationClient) {
            ((WorkloadIdentityFederationClient) federationClient).shutdown();
            LOG.debug("Authentication provider shut down");
        }
    }
}
