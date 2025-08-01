package com.oracle.bmc.auth.internal;

import com.oracle.bmc.auth.SessionKeySupplier;
import com.oracle.bmc.http.client.HttpClientBuilder;
import com.oracle.bmc.http.client.HttpProvider;
import com.oracle.bmc.http.client.Method;
import com.oracle.bmc.http.client.Serializer;
import org.slf4j.Logger;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CompletableFuture;

/**
 * This class implements the {@link FederationClient} interface and is
 * responsible for
 * exchanging a subject token for a security token from an identity domain.
 * It handles caching and refreshing of the security token in a thread-safe
 * manner.
 */
public class SubjectTokenExchangeAsyncFederationClient extends AbstractAsyncFederationClient {
        private static final Logger LOG = org.slf4j.LoggerFactory
                        .getLogger(SubjectTokenExchangeAsyncFederationClient.class);
        private final SubjectTokenSupplierImpl subjectTokenSupplier;
        private final String tokenExchangeEndpoint;
        private final String clientCredentials;
        private final Object refreshLock = new Object();

        /**
         * Constructs a new TokenExchangeFederationClient.
         *
         * @param tokenExchangeEndpoint The endpoint for token exchange.
         * @param subjectTokenSupplier  A supplier for the subject token.
         * @param sessionKeySupplier    A supplier for the session key.
         * @param clientCredentials     The client credentials for basic authentication.
         */
        public SubjectTokenExchangeAsyncFederationClient(
                        String tokenExchangeEndpoint,
                        SubjectTokenSupplierImpl subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials) {
                super(sessionKeySupplier);
                this.subjectTokenSupplier = subjectTokenSupplier;
                this.tokenExchangeEndpoint = tokenExchangeEndpoint;
                this.clientCredentials = clientCredentials;
                // Circuit breaker configuration and additional client configurators are not
                // used in this implementation
                LOG.debug("TokenExchangeFederationClient initialized with endpoint: {}", tokenExchangeEndpoint);
        }

        /**
         * Gets a security token. If the current token is still valid, it will be
         * returned.
         * Otherwise, a new token will be requested from the server. This method is
         * thread-safe.
         *
         * @return A security token.
         */
        @Override
        public CompletableFuture<String> getSecurityToken() {
                if (securityTokenAdapter.isValid()) {
                        return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
                }

                synchronized (refreshLock) {
                        // Re-check validity inside lock to prevent race conditions
                        if (securityTokenAdapter.isValid()) {
                                return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
                        }

                        LOG.debug("Security token is not valid, refreshing from server.");
                        sessionKeySupplier.refreshKeys();
                        CompletableFuture<String> future = new CompletableFuture<>();
                        getSecurityTokenFromServer()
                                        .whenComplete(
                                                        (newAdapter, error) -> {
                                                                if (error != null) {
                                                                        future.completeExceptionally(error);
                                                                } else {
                                                                        this.securityTokenAdapter = newAdapter;
                                                                        future.complete(this.securityTokenAdapter
                                                                                        .getSecurityToken());
                                                                }
                                                        });
                        return future;
                }
        }

        /**
         * Retrieves a new security token from the federation server by performing a
         * token exchange.
         *
         * @return A new {@link SecurityTokenAdapter} containing the security token.
         */
        @Override
        public CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer() {
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
                                future.completeExceptionally(new IllegalStateException("Public key must not be null"));
                                return future;
                        }

                        // Build HTTP client
                        HttpClientBuilder httpClientBuilder = HttpProvider.getDefault().newBuilder()
                                        .baseUri(URI.create(tokenExchangeEndpoint));

                        // Prepare basic auth header
                        String basicAuth = clientCredentials;
                        LOG.debug("Basic Auth Header (encoded): {}", basicAuth);

                        // Prepare request body for token endpoint (OAuth2 token exchange grant)
                        StringBuilder requestBodyBuilder = new StringBuilder();
                        requestBodyBuilder
                                        .append("grant_type=")
                                        .append(java.net.URLEncoder.encode(
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
                        // DER base64 encode the public key
                        String publicKeyDerBase64 = java.util.Base64.getEncoder()
                                        .encodeToString(publicKey.getEncoded());
                        requestBodyBuilder
                                        .append("&public_key=")
                                        .append(java.net.URLEncoder.encode(publicKeyDerBase64, "UTF-8"));

                        String requestBody = requestBodyBuilder.toString();

                        // Make HTTP POST call to token endpoint
                        return httpClientBuilder
                                        .build()
                                        .createRequest(Method.POST)
                                        .header("Authorization", "Basic " + basicAuth)
                                        .header("Content-Type", "application/x-www-form-urlencoded")
                                        .body(requestBody)
                                        .execute()
                                        .toCompletableFuture()
                                        .thenCompose(response -> {
                                                if (response.status() != 200) {
                                                        return response.textBody()
                                                                        .thenCompose(
                                                                                        body -> {
                                                                                                LOG.error("Token exchange request failed with status: {} and body: {}",
                                                                                                                response.status(),
                                                                                                                body);
                                                                                                CompletableFuture<SecurityTokenAdapter> failed = new CompletableFuture<>();
                                                                                                failed.completeExceptionally(
                                                                                                                new RuntimeException(
                                                                                                                                "Token exchange request failed with status: "
                                                                                                                                                + response.status()));
                                                                                                return failed;
                                                                                        });
                                                }
                                                return response.textBody()
                                                                .thenApply(
                                                                                body -> {
                                                                                        try {
                                                                                                java.util.Map<String, Object> responseMap = Serializer
                                                                                                                .getDefault()
                                                                                                                .readValue(body, java.util.Map.class);
                                                                                                Object accessTokenObj = responseMap
                                                                                                                .get("token");
                                                                                                String accessToken = accessTokenObj != null
                                                                                                                ? accessTokenObj.toString()
                                                                                                                : null;
                                                                                                LOG.debug("Token exchange response: {}",
                                                                                                                body);
                                                                                                return new SecurityTokenAdapter(
                                                                                                                accessToken,
                                                                                                                sessionKeySupplier);
                                                                                        } catch (java.io.IOException e) {
                                                                                                throw new RuntimeException(
                                                                                                                "Failed to parse token exchange response",
                                                                                                                e);
                                                                                        }
                                                                                });
                                        });
                } catch (Exception e) {
                        LOG.error("Unable to exchange token", e);
                        CompletableFuture<SecurityTokenAdapter> future = new CompletableFuture<>();
                        future.completeExceptionally(new RuntimeException("Unable to exchange token", e));
                        return future;
                }
        }

        /**
         * Forces a refresh of the security token. This will always fetch a new token
         * from the
         * federation server, regardless of the validity of the current token. This
         * method is thread-safe.
         *
         * @return The new security token.
         */
        @Override
        public CompletableFuture<String> refreshAndGetSecurityToken() {
                CompletableFuture<String> future = new CompletableFuture<>();
                synchronized (refreshLock) {
                        LOG.debug("Force refreshing keys and security token from Identity Domain");
                        sessionKeySupplier.refreshKeys();
                        getSecurityTokenFromServer()
                                        .whenComplete(
                                                        (newAdapter, error) -> {
                                                                if (error != null) {
                                                                        future.completeExceptionally(error);
                                                                } else {
                                                                        this.securityTokenAdapter = newAdapter;
                                                                        future.complete(this.securityTokenAdapter
                                                                                        .getSecurityToken());
                                                                }
                                                        });

                }
                return future;
        }

        /**
         * Gets a claim from the security token.
         *
         * @param key The claim key.
         * @return The claim value as a string.
         */
        @Override
        public String getStringClaim(String key) {
                return securityTokenAdapter.getStringClaim(key);
        }

}