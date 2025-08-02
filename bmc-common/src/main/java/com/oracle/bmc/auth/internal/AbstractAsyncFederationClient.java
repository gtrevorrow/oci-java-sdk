package com.oracle.bmc.auth.internal;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import com.oracle.bmc.auth.SessionKeySupplier;
import org.slf4j.Logger;
import java.util.Optional;

import com.oracle.bmc.auth.ProvidesConfigurableRefreshAsync;

public abstract class AbstractAsyncFederationClient implements AsyncFederationClient, ProvidesConfigurableRefreshAsync {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(AbstractAsyncFederationClient.class);
    protected volatile SecurityTokenAdapter securityTokenAdapter;
    protected final SessionKeySupplier sessionKeySupplier;
    private volatile CompletableFuture<SecurityTokenAdapter> pendingRefresh = null;
    private final Object refreshLock = new Object();

    public AbstractAsyncFederationClient(SessionKeySupplier sessionKeySupplier) {
        this.sessionKeySupplier = sessionKeySupplier;
        this.securityTokenAdapter = new SecurityTokenAdapter(null, sessionKeySupplier);
        LOG.debug("AbstractAsyncFederationClient initialized with session key supplier: {}", sessionKeySupplier);
    }

    public abstract CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer();

    @Override
    public CompletableFuture<String> refreshAndGetSecurityTokenIfExpiringWithin(Duration time) {
        return refreshAndGetSecurityTokenInnerAsync(true, Optional.of(time), true);
    }

    @Override
    public CompletableFuture<String> refreshAndGetSecurityTokenIfExpiringWithin(Duration time, boolean refreshKeys) {
        return refreshAndGetSecurityTokenInnerAsync(true, Optional.of(time), refreshKeys);
    }

    protected CompletableFuture<String> refreshAndGetSecurityTokenInnerAsync(
            final boolean doFinalTokenValidityCheck, Optional<Duration> time, boolean refreshKeys) {
        boolean isValid = securityTokenAdapter.isValid(time);
        if (doFinalTokenValidityCheck && isValid) {
            LOG.debug("Token is valid, returning existing token");
            return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
        }

        synchronized (refreshLock) {
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
            return pendingRefresh.thenApply(adapter -> {
                LOG.debug("Refresh completed, updating token adapter");
                securityTokenAdapter = adapter;
                return adapter.getSecurityToken();
            }).whenComplete((result, ex) -> {
                LOG.debug("Refresh future completed, clearing pendingRefresh");
                pendingRefresh = null;
            });
        }
    }
}