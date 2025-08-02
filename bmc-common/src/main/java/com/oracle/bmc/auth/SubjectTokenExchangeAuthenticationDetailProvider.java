package com.oracle.bmc.auth;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.function.Supplier;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AuthUtils;
import com.oracle.bmc.auth.AbstractRequestingAuthenticationDetailsProvider.CachingSessionKeySupplier;
import com.oracle.bmc.auth.internal.AbstractAsyncFederationClient;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenExchangeAsyncFederationClient;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import org.slf4j.Logger;

public class SubjectTokenExchangeAuthenticationDetailProvider
        implements BasicAuthenticationDetailsProvider, RegionProvider, RefreshableOnNotAuthenticatedProvider<String>,
        ProvidesConfigurableRefresh {

    private final String tokenExchangeUrl;
    private String securityToken;
    private String clientCredential;
    private AsyncFederationClient federationClient;
    private SessionKeySupplier sessionKeySupplier;
    private final Region region;

    public SubjectTokenExchangeAuthenticationDetailProvider(AsyncFederationClient federationClient,
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
        this.tokenExchangeUrl = tokenExchangeUrl;
        this.region = region;
    }

    public static class TokenExchangeAuthenticationDetailProviderBuilder {

        private String tokenExchangeUrl;
        private Region region;
        private SessionKeySupplier sessionKeySupplier;
        private AsyncFederationClient federationClient;
        private Supplier<String> subjectTokenSupplier;
        private String clientCredential;
        private static final Logger LOG = org.slf4j.LoggerFactory
                .getLogger(TokenExchangeAuthenticationDetailProviderBuilder.class);

        public TokenExchangeAuthenticationDetailProviderBuilder() {
        }

        /**
         * Creates a new AsyncFederationClient instance.
         *
         * @param sessionKeySupplier the session key supplier to use
         * @return a new AsyncFederationClient instance
         */
        protected AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
            if (this.federationClient == null) {
                this.federationClient = new SubjectTokenExchangeAsyncFederationClient(tokenExchangeUrl,
                        subjectTokenSupplier, sessionKeySupplier, clientCredential);
            }
            return this.federationClient;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder clientCredential(String clientCredential) {
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

        public TokenExchangeAuthenticationDetailProviderBuilder tokenExchangeUrl(String tokenExchangeUrl) {
            this.tokenExchangeUrl = tokenExchangeUrl;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder subjectTokenSupplier(
                Supplier<String> subjectTokenSupplier) {
            this.subjectTokenSupplier = subjectTokenSupplier;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder region(Region region) {
            this.region = region;
            return this;
        }

        public SubjectTokenExchangeAuthenticationDetailProvider build() {
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
            return new SubjectTokenExchangeAuthenticationDetailProvider(this.federationClient, this.sessionKeySupplier,
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
        if (federationClient instanceof AbstractAsyncFederationClient) {
            try {
                return ((AbstractAsyncFederationClient) federationClient)
                        .refreshAndGetSecurityTokenIfExpiringWithin(duration).get();
            } catch (Exception e) {
                throw new RuntimeException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage(), e);
            }
        }
        return refresh();
    }

    @Override
    public String refreshAndGetSecurityTokenIfExpiringWithin(Duration duration, boolean refreshKeys) {
        if (federationClient instanceof AbstractAsyncFederationClient) {
            try {
                return ((AbstractAsyncFederationClient) federationClient)
                        .refreshAndGetSecurityTokenIfExpiringWithin(duration, refreshKeys).get();
            } catch (Exception e) {
                throw new RuntimeException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage(), e);
            }
        }
        return refresh();
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