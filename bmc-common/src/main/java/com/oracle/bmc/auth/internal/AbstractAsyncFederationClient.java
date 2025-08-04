/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */


package com.oracle.bmc.auth.internal;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import com.oracle.bmc.auth.ProvidesConfigurableRefreshAsync;
import com.oracle.bmc.auth.SessionKeySupplier;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.circuitbreaker.OciCircuitBreaker;
import com.oracle.bmc.http.ClientConfigurator;
import com.oracle.bmc.http.client.HttpClient;
import com.oracle.bmc.http.client.HttpClientBuilder;
import com.oracle.bmc.http.client.HttpProvider;
import com.oracle.bmc.http.internal.CircuitBreakerHelper;
import org.slf4j.Logger;

import java.net.URI;
import java.util.List;
import java.util.Optional;
/**
 * Abstract base class for asynchronous federation clients that handle security token retrieval and refresh logic.
 * <p>
 * This class manages the lifecycle of security tokens, including refreshing tokens when they are about to expire,
 * and optionally refreshing session keys. It ensures that only one token refresh operation is in progress at any time,
 * and provides mechanisms to reuse pending refresh operations.
 * The class is thread-safe and uses a lock to synchronize access to the refresh logic.
 * </p>
 *
 * <p>
 * Subclasses must implement {@link #getSecurityTokenFromServer()} to define how security tokens are fetched from the server.
 * </p>
 *
 * @see AsyncFederationClient
 * @see ProvidesConfigurableRefreshAsync
 */
public abstract class AbstractAsyncFederationClient
        implements AsyncFederationClient, ProvidesConfigurableRefreshAsync {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(AbstractAsyncFederationClient.class);
    protected volatile SecurityTokenAdapter securityTokenAdapter; // volatile to ensure immediate visibility across threads
    protected final SessionKeySupplier sessionKeySupplier;
    protected final OciCircuitBreaker circuitBreaker;
    protected final HttpClient federationClient;
    private volatile CompletableFuture<SecurityTokenAdapter> pendingRefresh = null;
    private final Object refreshLock = new Object();

    public AbstractAsyncFederationClient(
            SessionKeySupplier sessionKeySupplier,
            String federationEndpoint,
            ClientConfigurator clientConfigurator,
            CircuitBreakerConfiguration circuitBreakerConfiguration,
            List<ClientConfigurator> additionalClientConfigurators) {
        this.sessionKeySupplier = sessionKeySupplier;
        this.securityTokenAdapter = new SecurityTokenAdapter(null, sessionKeySupplier);

        HttpClientBuilder rptBuilder = HttpProvider.getDefault().newBuilder().baseUri(URI.create(federationEndpoint));
        if (clientConfigurator != null) {
            clientConfigurator.customizeClient(rptBuilder);
        }
        for (ClientConfigurator additionalConfigurator : additionalClientConfigurators) {
            additionalConfigurator.customizeClient(rptBuilder);
        }
        this.federationClient = rptBuilder.build();

        if (this.federationClient != null) {
            this.circuitBreaker = CircuitBreakerHelper.makeCircuitBreaker(
                    this.federationClient, circuitBreakerConfiguration);
        } else {
            this.circuitBreaker = null;
        }

        LOG.debug(
                "AbstractAsyncFederationClient initialized with session key supplier: {}",
                sessionKeySupplier);
    }

    protected abstract CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer();

    @Override
    public CompletableFuture<String> refreshAndGetSecurityTokenIfExpiringWithin(Duration time) {
        return refreshAndGetSecurityTokenIfExpiringWithin(time, true);
    }

    @Override
    public CompletableFuture<String> refreshAndGetSecurityTokenIfExpiringWithin(
            Duration time, boolean refreshKeys) {
        return refreshAndGetSecurityTokenInnerAsync(true, time, refreshKeys);
    }

    @SuppressWarnings("ConstantConditions")
    protected CompletableFuture<String> refreshAndGetSecurityTokenInnerAsync(
            final boolean doFinalTokenValidityCheck, Duration time, boolean refreshKeys) {
        // double-check locking ...First check if the token is valid
        boolean isValid = securityTokenAdapter.isValid(Optional.ofNullable(time));

        if (doFinalTokenValidityCheck && isValid) {
            LOG.debug("Token is valid, returning existing token");
            return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
        }

        synchronized (refreshLock) {
            // double-check lcking  .. Check again after acquiring the lock
            if (pendingRefresh != null && !pendingRefresh.isCompletedExceptionally()) {
                LOG.debug("Reusing existing pending refresh: {}", pendingRefresh);
                return pendingRefresh.thenApply(SecurityTokenAdapter::getSecurityToken);
            }
            LOG.debug("Initiating new token refresh");
            if (refreshKeys) {
                LOG.info("Refreshing session keys.");
                sessionKeySupplier.refreshKeys();
            }
            pendingRefresh = getSecurityTokenFromServer();
            return pendingRefresh
                    .thenApply(
                            adapter -> {
                                LOG.debug("Refresh completed, updating token adapter");
                                securityTokenAdapter = adapter;
                                return adapter.getSecurityToken();
                            })
                    .whenComplete(
                            (result, ex) -> {
                                LOG.debug("Refresh future completed, clearing pendingRefresh");
                                pendingRefresh = null;
                            });
        }
    }

    public CompletableFuture<String> refreshAndGetSecurityToken() {
        return refreshAndGetSecurityTokenInnerAsync(true, null, true);
    }


    /**
     * Gets a security token from the federation endpoint. This will be a long-lived
     * token used to authenticate requests to OCI services.
     *
     * @return the security token
     */
    public CompletableFuture<String> getSecurityToken() {
        if (!securityTokenAdapter.isValid()) {
            return refreshAndGetSecurityToken();
        }
        return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
    }
}