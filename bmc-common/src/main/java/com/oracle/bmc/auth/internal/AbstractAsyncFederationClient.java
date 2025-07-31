package com.oracle.bmc.auth.internal;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import com.oracle.bmc.auth.ProvidesConfigurableRefresh;
import com.oracle.bmc.auth.SessionKeySupplier;

import org.slf4j.Logger;


import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Optional;

import com.oracle.bmc.auth.ProvidesConfigurableRefreshAsync;

public abstract class AbstractAsyncFederationClient implements AsyncFederationClient , ProvidesConfigurableRefreshAsync{
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(AbstractAsyncFederationClient.class);
    private static final ExecutorService ASYNC_REFRESH_EXECUTOR = Executors.newCachedThreadPool();
    protected volatile SecurityTokenAdapter securityTokenAdapter;
    protected final SessionKeySupplier sessionKeySupplier;

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
    public CompletableFuture<String> refreshAndGetSecurityTokenIfExpiringWithin(
            Duration time, boolean refreshKeys) {
        return refreshAndGetSecurityTokenInnerAsync(true, Optional.of(time), refreshKeys);
    }

    protected CompletableFuture<String> refreshAndGetSecurityTokenInnerAsync(
            final boolean doFinalTokenValidityCheck, Optional<Duration> time, boolean refreshKeys) {
        return CompletableFuture.supplyAsync(() -> {
            synchronized (this) {
                if (!doFinalTokenValidityCheck
                        || (time.isPresent()
                                ? (!securityTokenAdapter.isValid(time))
                                : (!securityTokenAdapter.isValid()))) {
                    if (refreshKeys) {
                        LOG.info("Refreshing session keys.");
                        sessionKeySupplier.refreshKeys();
                    }
                    // This part needs to be truly async, but getSecurityTokenFromServerAsync is abstract
                    // and needs to be implemented by concrete classes. For now, we'll call it synchronously
                    // within the supplyAsync block, assuming concrete implementations will make it non-blocking.
                    try {
                        securityTokenAdapter = getSecurityTokenFromServer().get(); // Blocking call here
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to get security token asynchronously", e);
                    }
                    return securityTokenAdapter.getSecurityToken();
                }
                return securityTokenAdapter.getSecurityToken();
            }
        }, ASYNC_REFRESH_EXECUTOR);
    }
}
    