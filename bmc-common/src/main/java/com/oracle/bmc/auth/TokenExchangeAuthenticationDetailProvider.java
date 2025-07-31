package com.oracle.bmc.auth;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AuthUtils;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.FederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenSupplierImpl;
import com.oracle.bmc.auth.internal.SubjectTokenExchangeAsyncFederationClient;
import java.io.ByteArrayInputStream;

public class TokenExchangeAuthenticationDetailProvider
        implements BasicAuthenticationDetailsProvider, RegionProvider, RefreshableOnNotAuthenticatedProvider<String>,
        ProvidesConfigurableRefresh {

    private final String tokenExchangeUrl;
    private final String subjectToken;
    private final String audience;
    private String securityToken;
    private String clientCredential;
    private AsyncFederationClient federationClient;
    private SessionKeySupplier sessionKeySupplier;
    private final Region region;

    public TokenExchangeAuthenticationDetailProvider(AsyncFederationClient federationClient,
            SessionKeySupplier sessionKeySupplier, String tokenExchangeUrl, String subjectToken, String audience,
            Region region) {
        this.federationClient= federationClient;
        this.sessionKeySupplier = sessionKeySupplier;
        this.tokenExchangeUrl = tokenExchangeUrl;
        this.subjectToken = subjectToken;
        this.audience = audience;
        this.region = region;
    }

    public static class TokenExchangeAuthenticationDetailProviderBuilder {

        private String tokenExchangeUrl;
        private String subjectToken;
        private String audience;
        private Region region;
        private SessionKeySupplier sessionKeySupplier;
        private AsyncFederationClient federationClient;
        private SubjectTokenSupplierImpl subjectTokenSupplierImpl;
        private String clientCredential;

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
                        subjectTokenSupplierImpl, sessionKeySupplier, clientCredential);
            }
            return this.federationClient;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder clientCredential(String clientCredential) {
            this.clientCredential = clientCredential;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder tokenExchangeUrl(String tokenExchangeUrl) {
            this.tokenExchangeUrl = tokenExchangeUrl;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder subjectToken(String subjectToken) {
            this.subjectToken = subjectToken;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder audience(String audience) {
            this.audience = audience;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder region(Region region) {
            this.region = region;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder sessionKeySupplier(
                SessionKeySupplier sessionKeySupplier) {
            this.sessionKeySupplier = sessionKeySupplier;
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder federationClient(
                AsyncFederationClient federationClient) {
            this.federationClient = federationClient;
            return this;
        }

        public TokenExchangeAuthenticationDetailProvider build() {
            return new TokenExchangeAuthenticationDetailProvider(federationClient, sessionKeySupplier, tokenExchangeUrl,
                    subjectToken, audience, region);
        }

        /**
         * Builds a TokenExchangeAuthenticationDetailProvider with the provided session
         * key supplier.
         *
         * @param sessionKeySupplierToUse the session key supplier to use
         * @return a new TokenExchangeAuthenticationDetailProvider instance
         */
        protected TokenExchangeAuthenticationDetailProvider buildProvider(SessionKeySupplier sessionKeySupplierToUse) {
            return new TokenExchangeAuthenticationDetailProvider(
                    federationClient, sessionKeySupplierToUse, tokenExchangeUrl, subjectToken, audience, region);
        }
    }

    @Override
    public String refreshAndGetSecurityTokenIfExpiringWithin(Duration time) {
        if (this.federationClient instanceof ProvidesConfigurableRefresh) {
            return ((ProvidesConfigurableRefresh) this.federationClient)
                    .refreshAndGetSecurityTokenIfExpiringWithin(time);
        }
        return this.federationClient.refreshAndGetSecurityToken().join();
    }

    @Override
    public String refreshAndGetSecurityTokenIfExpiringWithin(Duration time, boolean refreshKeys) {
        if (this.federationClient instanceof ProvidesConfigurableRefresh) {
            return ((ProvidesConfigurableRefresh) this.federationClient)
                    .refreshAndGetSecurityTokenIfExpiringWithin(time, refreshKeys);
        }
        return this.federationClient.refreshAndGetSecurityToken().join();
    }

    @Override
    public String refresh() {
        return this.federationClient.refreshAndGetSecurityToken().join();
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
        return new ByteArrayInputStream(AuthUtils.toByteArrayFromRSAPrivateKey((RSAPrivateKey)sessionKeySupplier.getKeyPair().getPrivate()));
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
