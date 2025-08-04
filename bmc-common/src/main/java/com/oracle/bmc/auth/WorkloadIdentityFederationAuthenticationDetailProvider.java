/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.function.Supplier;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AuthUtils;
import com.oracle.bmc.auth.AbstractRequestingAuthenticationDetailsProvider.CachingSessionKeySupplier;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.WorkloadIdentityFederationClient;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.http.ClientConfigurator;

import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;

@AuthCachingPolicy(cacheKeyId = false, cachePrivateKey = false)
public class WorkloadIdentityFederationAuthenticationDetailProvider
        implements BasicAuthenticationDetailsProvider, RegionProvider, RefreshableOnNotAuthenticatedProvider<String>,
        ProvidesConfigurableRefresh {

    private AsyncFederationClient federationClient;
    private SessionKeySupplier sessionKeySupplier;
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

                this.federationClient = new WorkloadIdentityFederationClient(
                        tokenExchangeUrl,
                        subjectTokenSupplier,
                        sessionKeySupplier,
                        clientCredential,
                        null, // No custom client configurator
                        circuitBreakerConfig,
                        Collections.emptyList(), // No additional client configurators
                        secondsToExpireSessionTokenEarly);
                LOG.debug(
                        "WorkloadIdentityFederationClient created with early expiration: {} seconds",
                        this.secondsToExpireSessionTokenEarly);
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
        return new ByteArrayInputStream(
                AuthUtils.toByteArrayFromRSAPrivateKey((RSAPrivateKey) sessionKeySupplier.getKeyPair().getPrivate()));
    }

    @Override
    public String getPassPhrase() {
        return null; // Not applicable for token exchange
    }

    @Override
    public char[] getPassphraseCharacters() {
        return null; // Not applicable for token exchange
    }
}
