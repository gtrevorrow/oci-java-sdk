/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth.internal;

import com.oracle.bmc.auth.SessionKeySupplier;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.http.ClientConfigurator;
import com.oracle.bmc.http.client.Method;
import com.oracle.bmc.http.client.Serializer;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class WorkloadIdentityFederationClient extends AbstractAsyncFederationClient {
        private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(WorkloadIdentityFederationClient.class);
        private final Supplier<String> subjectTokenSupplier;
        private final String clientCredentials;
        private Long secondsToExpireSessionTokenEarly;

        public WorkloadIdentityFederationClient(
                        String tokenExchangeEndpoint,
                        Supplier<String> subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials,
                        ClientConfigurator clientConfigurator,
                        CircuitBreakerConfiguration circuitBreakerConfiguration,
                        List<ClientConfigurator> additionalClientConfigurators,
                        Long secondsToExpireSessionTokenEarly) {
                super(
                                sessionKeySupplier,
                                tokenExchangeEndpoint,
                                clientConfigurator,
                                circuitBreakerConfiguration,
                                additionalClientConfigurators);
                this.subjectTokenSupplier = subjectTokenSupplier;
                this.clientCredentials = clientCredentials;
                this.secondsToExpireSessionTokenEarly = secondsToExpireSessionTokenEarly != null
                                ? secondsToExpireSessionTokenEarly
                                : 300L;
                LOG.debug(
                                "TokenExchangeFederationClient initialized with endpoint: {}",
                                tokenExchangeEndpoint);
        }

        public WorkloadIdentityFederationClient(
                        String tokenExchangeEndpoint,
                        Supplier<String> subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials,
                        ClientConfigurator clientConfigurator,
                        CircuitBreakerConfiguration circuitBreakerConfiguration,
                        List<ClientConfigurator> additionalClientConfigurators) {
                this(
                                tokenExchangeEndpoint,
                                subjectTokenSupplier,
                                sessionKeySupplier,
                                clientCredentials,
                                clientConfigurator,
                                circuitBreakerConfiguration,
                                additionalClientConfigurators,
                                null);
        }

        public WorkloadIdentityFederationClient(
                        String tokenExchangeEndpoint,
                        Supplier<String> subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials) {
                this(
                                tokenExchangeEndpoint,
                                subjectTokenSupplier,
                                sessionKeySupplier,
                                clientCredentials,
                                null,
                                null,
                                Collections.emptyList(),
                                null);
        }

        public WorkloadIdentityFederationClient(
                        String tokenExchangeEndpoint,
                        Supplier<String> subjectTokenSupplier,
                        SessionKeySupplier sessionKeySupplier,
                        String clientCredentials,
                        Long secondsToExpireSessionTokenEarly) {
                this(
                                tokenExchangeEndpoint,
                                subjectTokenSupplier,
                                sessionKeySupplier,
                                clientCredentials,
                                null,
                                null,
                                Collections.emptyList(),
                                secondsToExpireSessionTokenEarly);
        }

        @Override
        public CompletableFuture<String> getSecurityToken() {
                return refreshAndGetSecurityTokenIfExpiringWithin(
                                Duration.ofSeconds(secondsToExpireSessionTokenEarly));
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
                                future.completeExceptionally(
                                                new IllegalStateException("Public key must not be null"));
                                return future;
                        }

                        String basicAuth = clientCredentials;
                        LOG.debug("Basic Auth Header (encoded): {}", basicAuth);

                        StringBuilder requestBodyBuilder = new StringBuilder();
                        requestBodyBuilder
                                        .append("grant_type=")
                                        .append(
                                                        java.net.URLEncoder.encode(
                                                                        "urn:ietf:params:oauth:grant-type:token-exchange",
                                                                        "UTF-8"));
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

                        return federationClient
                                        .createRequest(Method.POST)
                                        .header("Authorization", "Basic " + basicAuth)
                                        .header("Content-Type", "application/x-www-form-urlencoded")
                                        .body(requestBody)
                                        .execute()
                                        .toCompletableFuture()
                                        .thenCompose(
                                                        response -> {
                                                                if (response.status() != 200) {
                                                                        return response.textBody()
                                                                                        .thenCompose(
                                                                                                        body -> {
                                                                                                                LOG.error(
                                                                                                                                "Token exchange request failed with status: {} and body: {}",
                                                                                                                                response.status(),
                                                                                                                                body);
                                                                                                                CompletableFuture<SecurityTokenAdapter> failed = new CompletableFuture<>();
                                                                                                                failed.completeExceptionally(
                                                                                                                                new RuntimeException(
                                                                                                                                                "Token exchange request failed with status: "
                                                                                                                                                                + response
                                                                                                                                                                                .status()));
                                                                                                                return failed;
                                                                                                        });
                                                                }
                                                                return response.textBody()
                                                                                .thenApply(
                                                                                                body -> {
                                                                                                        try {
                                                                                                                @SuppressWarnings("unchecked")
                                                                                                                Map<String, Object> responseMap = Serializer
                                                                                                                                .getDefault()
                                                                                                                                .readValue(
                                                                                                                                                body,
                                                                                                                                                Map.class);
                                                                                                                Object accessTokenObj = responseMap
                                                                                                                                .get("token");
                                                                                                                String accessToken = accessTokenObj != null
                                                                                                                                ? accessTokenObj.toString()
                                                                                                                                : null;
                                                                                                                LOG.debug(
                                                                                                                                "Token exchange response: {}",
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

        @Override
        public String getStringClaim(String key) {
                return securityTokenAdapter.getStringClaim(key);
        }
}