package com.oracle.bmc.auth;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AuthUtils;
import com.oracle.bmc.auth.AbstractFederationClientAuthenticationDetailsProviderBuilder.SessionKeySupplierImpl;
import com.oracle.bmc.auth.AbstractRequestingAuthenticationDetailsProvider.CachingSessionKeySupplier;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenSupplierImpl;
import com.oracle.bmc.auth.internal.SubjectTokenExchangeAsyncFederationClient;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import org.slf4j.Logger;

public class SubjectTokenExchangeAuthenticationDetailProvider
        implements BasicAuthenticationDetailsProvider, RegionProvider, RefreshableOnNotAuthenticatedProvider<String>,
        ProvidesConfigurableRefresh {

    private final String tokenExchangeUrl;
    private final String subjectToken;
    private String securityToken;
    private String clientCredential;
    private AsyncFederationClient federationClient;
    private SessionKeySupplier sessionKeySupplier;
    private final Region region;

    public SubjectTokenExchangeAuthenticationDetailProvider(AsyncFederationClient federationClient,
            SessionKeySupplier sessionKeySupplier, String tokenExchangeUrl, String subjectToken,
            Region region) {
        this.federationClient = federationClient;
        this.sessionKeySupplier = sessionKeySupplier;
        this.tokenExchangeUrl = tokenExchangeUrl;
        this.subjectToken = subjectToken;
        this.region = region;
    }

    public static class TokenExchangeAuthenticationDetailProviderBuilder {

        private String tokenExchangeUrl;
        private String subjectToken;
        private Region region;
        private SessionKeySupplier sessionKeySupplier;
        private AsyncFederationClient federationClient;
        private SubjectTokenSupplierImpl subjectTokenSupplierImpl;
        private String clientCredential;
        private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(TokenExchangeAuthenticationDetailProviderBuilder.class);

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

        public TokenExchangeAuthenticationDetailProviderBuilder subjectToken(
                SubjectTokenSupplierImpl subjectTokenSupplierImpl) {
            this.subjectTokenSupplierImpl = subjectTokenSupplierImpl;
            this.subjectToken = subjectTokenSupplierImpl.get();
            return this;
        }

        public TokenExchangeAuthenticationDetailProviderBuilder region(Region region) {
            this.region = region;
            return this;
        }

        // public TokenExchangeAuthenticationDetailProviderBuilder sessionKeySupplier(
        // SessionKeySupplier sessionKeySupplier) {
        // this.sessionKeySupplier = sessionKeySupplier;
        // return this;
        // }

        // public TokenExchangeAuthenticationDetailProviderBuilder federationClient(
        // AsyncFederationClient federationClient) {
        // this.federationClient = federationClient;
        // return this;
        // }

        public SubjectTokenExchangeAuthenticationDetailProvider build() {
            SessionKeySupplier sessionKeySupplierToUse = sessionKeySupplier != null ? sessionKeySupplier
                    : new SessionKeySupplierImpl();
            this.sessionKeySupplier = new CachingSessionKeySupplier(sessionKeySupplierToUse);
            this.federationClient = createFederationClient(sessionKeySupplierToUse);
            return new SubjectTokenExchangeAuthenticationDetailProvider(this.federationClient, this.sessionKeySupplier,
                    this.tokenExchangeUrl,
                    this.subjectToken, region);
        }

        // /**
        // * Builds a TokenExchangeAuthenticationDetailProvider with the provided
        // session
        // * key supplier.
        // *
        // * @param sessionKeySupplierToUse the session key supplier to use
        // * @return a new TokenExchangeAuthenticationDetailProvider instance
        // */
        // protected SubjectTokenExchangeAuthenticationDetailProvider buildProvider(
        // SessionKeySupplier sessionKeySupplierToUse) {
        // return new SubjectTokenExchangeAuthenticationDetailProvider(
        // federationClient, sessionKeySupplierToUse, tokenExchangeUrl, subjectToken,
        // region);
        // }
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
