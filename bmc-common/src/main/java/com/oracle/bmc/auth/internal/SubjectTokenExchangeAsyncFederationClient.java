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
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class SubjectTokenExchangeAsyncFederationClient extends AbstractAsyncFederationClient {
        private static final Logger LOG = org.slf4j.LoggerFactory
                        .getLogger(SubjectTokenExchangeAsyncFederationClient.class);
        private final Supplier<String> subjectTokenSupplier;
        private final String tokenExchangeEndpoint;
        private final String clientCredentials;
        private final Object refreshLock = new Object();
        private volatile CompletableFuture<SecurityTokenAdapter> pendingRefresh = null;

        public SubjectTokenExchangeAsyncFederationClient(
                        String tokenExchangeEndpoint,
                        Supplier<String> subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials) {
                super(sessionKeySupplier);
                this.subjectTokenSupplier = subjectTokenSupplier;
                this.tokenExchangeEndpoint = tokenExchangeEndpoint;
                this.clientCredentials = clientCredentials;
                LOG.debug("TokenExchangeFederationClient initialized with endpoint: {}", tokenExchangeEndpoint);
        }

        @Override
        public CompletableFuture<String> getSecurityToken() {
                // Optimistic check to avoid synchronization if token is valid
                if (securityTokenAdapter.isValid()) {
                        return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
                }

                synchronized (refreshLock) {
                        // Double-check validity within lock
                        if (securityTokenAdapter.isValid()) {
                                return CompletableFuture.completedFuture(securityTokenAdapter.getSecurityToken());
                        }

                        // Check for ongoing refresh
                        if (pendingRefresh != null && !pendingRefresh.isCompletedExceptionally()) {
                                LOG.debug("Reusing ongoing token refresh operation.");
                                return pendingRefresh.thenApply(SecurityTokenAdapter::getSecurityToken);
                        }

                        LOG.debug("Security token is not valid, initiating refresh from server.");
                        sessionKeySupplier.refreshKeys();
                        pendingRefresh = getSecurityTokenFromServer();
                        return pendingRefresh.thenApply(adapter -> {
                                synchronized (refreshLock) {
                                        securityTokenAdapter = adapter;
                                        return adapter.getSecurityToken();
                                }
                        }).whenComplete((result, ex) -> {
                                synchronized (refreshLock) {
                                        pendingRefresh = null; // Clear pending refresh
                                }
                        });
                }
        }

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

                        HttpClientBuilder httpClientBuilder = HttpProvider.getDefault().newBuilder()
                                        .baseUri(URI.create(tokenExchangeEndpoint));

                        String basicAuth = clientCredentials;
                        LOG.debug("Basic Auth Header (encoded): {}", basicAuth);

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
                        String publicKeyDerBase64 = java.util.Base64.getEncoder()
                                        .encodeToString(publicKey.getEncoded());
                        requestBodyBuilder
                                        .append("&public_key=")
                                        .append(java.net.URLEncoder.encode(publicKeyDerBase64, "UTF-8"));

                        String requestBody = requestBodyBuilder.toString();

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

        @Override
        public CompletableFuture<String> refreshAndGetSecurityToken() {
                // Delegate to the parent's coordinated refresh logic
                return refreshAndGetSecurityTokenInnerAsync(true, Optional.empty(), true);
        }
        // @Override
        // public CompletableFuture<String> refreshAndGetSecurityToken() {
        // synchronized (refreshLock) {
        // LOG.debug("Force refreshing keys and security token from Identity Domain");
        // // Check for ongoing refresh
        // if (pendingRefresh != null && !pendingRefresh.isCompletedExceptionally()) {
        // LOG.debug("Reusing ongoing token refresh operation for forced refresh.");
        // return pendingRefresh.thenApply(SecurityTokenAdapter::getSecurityToken);
        // }

        // sessionKeySupplier.refreshKeys();
        // pendingRefresh = getSecurityTokenFromServer();
        // return pendingRefresh.thenApply(adapter -> {
        // synchronized (refreshLock) {
        // securityTokenAdapter = adapter;
        // return adapter.getSecurityToken();
        // }
        // }).whenComplete((result, ex) -> {
        // synchronized (refreshLock) {
        // pendingRefresh = null; // Clear pending refresh
        // }
        // });
        // }
        // }

        @Override
        public String getStringClaim(String key) {
                return securityTokenAdapter.getStringClaim(key);
        }
}