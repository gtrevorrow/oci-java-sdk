/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AsyncFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenExchangeAsyncFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenSupplierImpl;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.nio.charset.StandardCharsets;

import com.oracle.bmc.util.StreamUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

@RunWith(MockitoJUnitRunner.Silent.class)
public class SubjectTokenExchangeAuthenticationDetailProviderTest {

        @Mock
        private AsyncFederationClient mockFederationClient;

        @Mock
        private SessionKeySupplier mockSessionKeySupplier;
        @Mock
        private java.security.interfaces.RSAPrivateKey mockPrivateKey;
        @Mock
        private PublicKey mockPublicKey;

        private static final String MOCK_TOKEN_EXCHANGE_URL = "https://idcs-5d9e793985524e1c80b5d96f9a03acb7.identity.oraclecloud.com:443/oauth2/v1/token";
        private static final String MOCK_SUBJECT_TOKEN = "mockSubjectToken";
        private static final Region MOCK_REGION = Region.US_ASHBURN_1;
        private static final String MOCK_SECURITY_TOKEN = "mockSecurityToken";
        private static final String MOCK_NEW_SECURITY_TOKEN = "mockNewSecurityToken";
        private static final String MOCK_CLIENT_CREDENTIAL = "mockClientCredential";
        private String expectedPrivateKeyContent;

        @Before
        public void setUp() {
                // Stubbing common behavior for mockFederationClient
                // This ensures that calls to getSecurityToken() and
                // refreshAndGetSecurityToken()
                // on the mock return a predictable value, which is essential for tests
                // that rely on the provider's interaction with the federation client.
                when(mockFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                // Ensure the session key supplier returns a valid key pair for private key
                // operations.
                when(mockSessionKeySupplier.getKeyPair()).thenReturn(new KeyPair(mockPublicKey, mockPrivateKey));
                // Load a real PKCS1 private key from resources for mocking
                // This is necessary because AuthUtils.toByteArrayFromRSAPrivateKey expects a
                // valid
                // RSAPrivateKey with encoded bytes, which a simple Mockito mock cannot provide
                // by default.
                try {
                        expectedPrivateKeyContent = new String(
                                        java.nio.file.Files
                                                        .readAllBytes(java.nio.file.Paths.get(
                                                                        "src/test/resources/pkcs1_private_key.pem")),
                                        java.nio.charset.StandardCharsets.UTF_8);
                        String base64EncodedKey = expectedPrivateKeyContent
                                        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                                        .replace("-----END RSA PRIVATE KEY-----", "")
                                        .replaceAll("\\s", ""); // Remove all whitespace
                        when(mockPrivateKey.getEncoded())
                                        .thenReturn(java.util.Base64.getDecoder().decode(base64EncodedKey));
                } catch (java.io.IOException e) {
                        throw new RuntimeException("Failed to load private key for test", e);
                }
        }

        @Test
        public void testConstructorAndGetters() {
                SubjectTokenExchangeAuthenticationDetailProvider provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_SUBJECT_TOKEN,
                                MOCK_REGION);

                assertNotNull(provider);
                assertEquals(MOCK_REGION, provider.getRegion());
                assertEquals("ST$" + MOCK_SECURITY_TOKEN, provider.getKeyId());
                assertNull(provider.getPassPhrase());
                assertNull(provider.getPassphraseCharacters());
                verify(mockFederationClient).getSecurityToken();
        }

        @Test
        public void testBuilder() {
                SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder builder =
                        org.mockito.Mockito.spy(new SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder());

                when(builder.createFederationClient(any(SessionKeySupplier.class))).thenReturn(mockFederationClient);

                SubjectTokenExchangeAuthenticationDetailProvider provider = builder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectToken(new SubjectTokenSupplierImpl(MOCK_SUBJECT_TOKEN))
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .build();

                assertNotNull(provider);
                assertEquals(MOCK_REGION, provider.getRegion());
                assertEquals("ST$" + MOCK_SECURITY_TOKEN, provider.getKeyId());
                verify(mockFederationClient).getSecurityToken();
        }

        @Test
        public void testRefresh() {
                SubjectTokenExchangeAuthenticationDetailProvider provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_SUBJECT_TOKEN,
                                MOCK_REGION);

                assertEquals(MOCK_SECURITY_TOKEN, provider.refresh());
                verify(mockFederationClient).refreshAndGetSecurityToken();
        }

        @Test
        public void testRefreshAndGetSecurityTokenIfExpiringWithin_nonConfigurableClient() {
                // This test case covers the scenario where the underlying federation client
                // does NOT implement ProvidesConfigurableRefresh. In this case, the provider
                // should fall back to calling refreshAndGetSecurityToken() on the base client.
                SubjectTokenExchangeAuthenticationDetailProvider provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_SUBJECT_TOKEN,
                                MOCK_REGION);

                assertEquals(MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5)));
                assertEquals(MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5), true));
                // Verify that refreshAndGetSecurityToken() was called twice (once for each call
                // to the provider's method)
                verify(mockFederationClient, org.mockito.Mockito.times(2)).refreshAndGetSecurityToken();
        }

        @Test
        public void testRefreshAndGetSecurityTokenIfExpiringWithin_configurableClient() {
                // This test case covers the scenario where the underlying federation client
                // DOES implement ProvidesConfigurableRefresh. The provider should delegate
                // the call directly to the configurable client's method.
                AsyncFederationClient configurableFederationClient = mock(AsyncFederationClient.class,
                                withSettings().extraInterfaces(ProvidesConfigurableRefresh.class));
                // Stubbing behavior for the configurable client when it's treated as
                // AsyncFederationClient
                when(configurableFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(configurableFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                // Stubbing behavior for the configurable client when it's treated as
                // ProvidesConfigurableRefresh
                when(((ProvidesConfigurableRefresh) configurableFederationClient)
                                .refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class)))
                                .thenReturn(MOCK_NEW_SECURITY_TOKEN);
                when(((ProvidesConfigurableRefresh) configurableFederationClient)
                                .refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class), any(Boolean.class)))
                                .thenReturn(MOCK_NEW_SECURITY_TOKEN);

                SubjectTokenExchangeAuthenticationDetailProvider provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                configurableFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_SUBJECT_TOKEN,
                                MOCK_REGION);

                assertEquals(MOCK_NEW_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5)));
                assertEquals(MOCK_NEW_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5), true));
                // Verify that the specific methods on ProvidesConfigurableRefresh were called
                verify((ProvidesConfigurableRefresh) configurableFederationClient)
                                .refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5));
                verify((ProvidesConfigurableRefresh) configurableFederationClient)
                                .refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5), true);
        }

        @Test
        public void testGetPrivateKey() {
                SubjectTokenExchangeAuthenticationDetailProvider provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_SUBJECT_TOKEN,
                                MOCK_REGION);

                InputStream privateKeyStream = provider.getPrivateKey();
                assertNotNull(privateKeyStream);
                verify(mockSessionKeySupplier).getKeyPair();
        }
}
