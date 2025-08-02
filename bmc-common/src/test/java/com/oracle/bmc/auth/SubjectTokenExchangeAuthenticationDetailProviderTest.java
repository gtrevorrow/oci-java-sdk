/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates. All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AbstractAsyncFederationClient;
import com.oracle.bmc.auth.internal.SecurityTokenAdapter;
import com.oracle.bmc.auth.internal.SubjectTokenExchangeAsyncFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenSupplierImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import org.slf4j.Logger;

@RunWith(MockitoJUnitRunner.Silent.class)
public class SubjectTokenExchangeAuthenticationDetailProviderTest {

        private static final Logger LOG = LoggerFactory
                        .getLogger(SubjectTokenExchangeAuthenticationDetailProviderTest.class);

        @Mock
        private SubjectTokenExchangeAsyncFederationClient mockFederationClient;

        @Mock
        private SessionKeySupplier mockSessionKeySupplier;
        @Mock
        private Supplier<String> mockSubjectTokenSupplier;

        private static final String MOCK_TOKEN_EXCHANGE_URL = "https://idcs-5d9e793985524e1c80b5d96f9a03acb7.identity.oraclecloud.com:443/oauth2/v1/token";
        private static final String MOCK_SUBJECT_TOKEN = "mockSubjectToken";
        private static final Region MOCK_REGION = Region.US_ASHBURN_1;
        private static final String MOCK_SECURITY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.z6B2J3i6vU-s2gT_FnMoIVLgT2-D4_ppo5aT2t8W3gY";
        private static final String MOCK_NEW_SECURITY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.z6B2J3i6vU-s2gT_FnMoIVLgT2-D4_ppo5aT2t8W3gY";
        private static final String MOCK_CLIENT_CREDENTIAL = "mockClientCredential";
        private SubjectTokenExchangeAuthenticationDetailProvider provider;

        @Before
        public void setUp() {
                // Stub common behavior for mockFederationClient
                when(mockFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class)))
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class),
                                any(Boolean.class)))
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Stub subject token supplier for tests needing it
                when(mockSubjectTokenSupplier.get()).thenReturn(MOCK_SUBJECT_TOKEN);
        }

        @After
        public void tearDown() {
                // Nullify the provider to ensure clean state between tests
                provider = null;
        }

        private void setupMockKeyPair() {
                KeyPair mockKeyPair = new KeyPair(mock(PublicKey.class), mock(RSAPrivateKey.class));
                when(mockSessionKeySupplier.getKeyPair()).thenReturn(mockKeyPair);
        }

        @Test
        public void constructorInitializesRegionAndKeyId() {
                setupMockKeyPair();
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                assertNotNull(provider);
                assertEquals(MOCK_REGION, provider.getRegion());
                assertEquals("ST$" + MOCK_SECURITY_TOKEN, provider.getKeyId());
                assertNull(provider.getPassPhrase());
                assertNull(provider.getPassphraseCharacters());
                verify(mockFederationClient).getSecurityToken();
        }

        @Test(expected = IllegalArgumentException.class)
        public void constructorThrowsOnNullFederationClient() {
                new SubjectTokenExchangeAuthenticationDetailProvider(
                                null, mockSessionKeySupplier, MOCK_TOKEN_EXCHANGE_URL, MOCK_REGION);
        }

        @Test(expected = IllegalArgumentException.class)
        public void constructorThrowsOnEmptyTokenExchangeUrl() {
                new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient, mockSessionKeySupplier, "", MOCK_REGION);
        }

        @Test
        public void builderCreatesProviderWithCorrectConfiguration() {
                SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder builder = mock(
                                SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder.class,
                                withSettings().defaultAnswer(CALLS_REAL_METHODS));
                when(builder.createFederationClient(any(SessionKeySupplier.class)))
                                .thenReturn(mockFederationClient);

                provider = builder.tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(new SubjectTokenSupplierImpl(MOCK_SUBJECT_TOKEN))
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .build();

                assertNotNull(provider);
                assertEquals(MOCK_REGION, provider.getRegion());
                assertEquals("ST$" + MOCK_SECURITY_TOKEN, provider.getKeyId());
                verify(mockFederationClient).getSecurityToken();
        }

        @Test(expected = IllegalArgumentException.class)
        public void builderThrowsOnMissingTokenExchangeUrl() {
                new SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder()
                                .subjectTokenSupplier(new SubjectTokenSupplierImpl(MOCK_SUBJECT_TOKEN))
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .build();
        }

        @Test(expected = IllegalArgumentException.class)
        public void builderThrowsOnNullSubjectTokenSupplier() {
                new SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder()
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(null)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .build();
        }

        @Test
        public void refreshReturnsTokenFromFederationClient() {
                setupMockKeyPair();
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                assertEquals(MOCK_SECURITY_TOKEN, provider.refresh());
                verify(mockFederationClient).refreshAndGetSecurityToken();
        }

        @Test
        public void refreshHandlesFederationClientFailure() {
                setupMockKeyPair();
                CompletableFuture<String> failedFuture = new CompletableFuture<>();
                failedFuture.completeExceptionally(new RuntimeException("Token refresh failed"));
                when(mockFederationClient.refreshAndGetSecurityToken()).thenReturn(failedFuture);

                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                try {
                        provider.refresh();
                        fail("Expected RuntimeException");
                } catch (RuntimeException e) {
                        assertEquals("Token refresh failed", e.getMessage());
                }
                verify(mockFederationClient).refreshAndGetSecurityToken();
        }

        @Test
        public void concurrentRefreshReusesPendingRefresh() throws Exception {
                // Use a real SessionKeySupplier
                SessionKeySupplier realKeySupplier = new SessionKeySupplierImpl();

                // Create real SubjectTokenExchangeAsyncFederationClient
                SubjectTokenExchangeAsyncFederationClient federationClient = new SubjectTokenExchangeAsyncFederationClient(
                                MOCK_TOKEN_EXCHANGE_URL,
                                mockSubjectTokenSupplier,
                                realKeySupplier,
                                MOCK_CLIENT_CREDENTIAL);

                // Mock initial SecurityTokenAdapter to force refresh
                SecurityTokenAdapter mockTokenAdapter = mock(SecurityTokenAdapter.class);
                when(mockTokenAdapter.isValid()).thenReturn(false);
                when(mockTokenAdapter.getSecurityToken()).thenReturn(MOCK_SECURITY_TOKEN);

                // Set initial token adapter via reflection
                java.lang.reflect.Field tokenAdapterField = AbstractAsyncFederationClient.class
                                .getDeclaredField("securityTokenAdapter");
                tokenAdapterField.setAccessible(true);
                tokenAdapterField.set(federationClient, mockTokenAdapter);

                // Custom wrapper to count and debug getSecurityTokenFromServer calls
                class CountingFederationClient extends SubjectTokenExchangeAsyncFederationClient {
                        private int serverCallCount = 0;
                        private final CompletableFuture<SecurityTokenAdapter> serverFuture;
                        private final CountDownLatch firstCallLatch = new CountDownLatch(1);

                        CountingFederationClient(String tokenExchangeEndpoint, Supplier<String> subjectTokenSupplier,
                                        SessionKeySupplier sessionKeySupplier, String clientCredentials,
                                        CompletableFuture<SecurityTokenAdapter> serverFuture) {
                                super(tokenExchangeEndpoint, subjectTokenSupplier, sessionKeySupplier,
                                                clientCredentials);
                                System.out.println(
                                                "Created CountingFederationClient: " + System.identityHashCode(this));
                                this.serverFuture = serverFuture;
                        }

                        @Override
                        public CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer() {
                                serverCallCount++;
                                System.out.println("getSecurityTokenFromServer called, count: " + serverCallCount
                                                + ", thread: " + Thread.currentThread().getName());
                                if (serverCallCount == 1) {
                                        firstCallLatch.countDown();
                                }
                                return serverFuture;
                        }

                        int getServerCallCount() {
                                return serverCallCount;
                        }

                        CountDownLatch getFirstCallLatch() {
                                return firstCallLatch;
                        }
                }

                // Create counting wrapper
                CompletableFuture<SecurityTokenAdapter> serverFuture = new CompletableFuture<>();
                CountingFederationClient countingClient = new CountingFederationClient(
                                MOCK_TOKEN_EXCHANGE_URL,
                                mockSubjectTokenSupplier,
                                realKeySupplier,
                                MOCK_CLIENT_CREDENTIAL,
                                serverFuture);

                // Initialize provider
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                countingClient,
                                realKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                // Launch 5 concurrent refresh tasks with controlled execution
                int concurrentThreads = 5;
                ExecutorService executor = Executors.newFixedThreadPool(concurrentThreads);
                Semaphore startSemaphore = new Semaphore(0);
                Semaphore completeSemaphore = new Semaphore(0);
                CompletableFuture<String>[] refreshFutures = new CompletableFuture[concurrentThreads];
                for (int i = 0; i < concurrentThreads; i++) {
                        final int threadIndex = i;
                        refreshFutures[i] = CompletableFuture.supplyAsync(() -> {
                                System.out.println("Thread " + threadIndex + " starting refresh");
                                startSemaphore.release(); // Signal thread has started
                                try {
                                        String result = provider.refresh(); // Blocks on .get()
                                        System.out.println("Thread " + threadIndex + " completed refresh, result: "
                                                        + result);
                                        completeSemaphore.release();
                                        return result;
                                } catch (Exception e) {
                                        System.err.println(
                                                        "Thread " + threadIndex + " refresh failed: " + e.getMessage());
                                        throw e;
                                }
                        }, executor);
                }

                // Wait for all threads to start
                System.out.println("Waiting for all threads to start");
                startSemaphore.acquire(concurrentThreads);

                // Wait for the first call to getSecurityTokenFromServer
                System.out.println("Waiting for first call to getSecurityTokenFromServer");
                countingClient.getFirstCallLatch().await();

                // Complete the server future
                System.out.println("Completing server future");
                SecurityTokenAdapter newTokenAdapter = new SecurityTokenAdapter(MOCK_NEW_SECURITY_TOKEN,
                                realKeySupplier);
                serverFuture.complete(newTokenAdapter);

                // Wait for all threads to complete
                System.out.println("Waiting for all threads to complete");
                completeSemaphore.acquire(concurrentThreads);

                // Shutdown executor
                executor.shutdown();
                executor.awaitTermination(10, TimeUnit.SECONDS);

                // Verify results
                for (int i = 0; i < concurrentThreads; i++) {
                        assertEquals("Thread " + i + " should return new security token", MOCK_NEW_SECURITY_TOKEN,
                                        refreshFutures[i].get());
                }

                // Verify call count
                int callCount = countingClient.getServerCallCount();
                System.out.println("Final server call count: " + callCount);
                assertEquals("Expected exactly one call to getSecurityTokenFromServer", 1, callCount);
        }

        @Test
        public void refreshAndGetSecurityTokenIfExpiringWithinNonConfigurableClient() {
                setupMockKeyPair();
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                assertEquals(
                                MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5)));
                assertEquals(
                                MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5), true));

                // Verify the actual method calls that are made
                verify(mockFederationClient, times(1))
                                .refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5));
                verify(mockFederationClient, times(1)).refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5),
                                true);
        }

        @Test
        public void refreshAndGetSecurityTokenIfExpiringWithinConfigurableClient() {
                setupMockKeyPair();
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                assertEquals(
                                MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5)));
                assertEquals(
                                MOCK_SECURITY_TOKEN,
                                provider.refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5), true));

                // Verify the actual method calls that are made
                verify(mockFederationClient, times(1))
                                .refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5));
                verify(mockFederationClient, times(1)).refreshAndGetSecurityTokenIfExpiringWithin(Duration.ofMinutes(5),
                                true);
        }

        @Test
        public void getPrivateKeyReturnsAValidKey()
                        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
                // Use a real key supplier for this test
                SessionKeySupplier realSessionKeySupplier = new SessionKeySupplierImpl();

                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                realSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                // Just verify we can get a private key stream without errors
                java.io.InputStream privateKeyStream = provider.getPrivateKey();
                assertNotNull("Private key stream should not be null", privateKeyStream);

                byte[] keyBytes = privateKeyStream.readAllBytes();
                assertTrue("Key bytes should not be empty", keyBytes.length > 0);
        }

        @Test
        public void getPrivateKeyHandlesNullKeyPair() {
                when(mockSessionKeySupplier.getKeyPair()).thenReturn(null);
                provider = new SubjectTokenExchangeAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                // The provider code doesn't handle null KeyPair gracefully, so expect an
                // exception
                assertThrows(
                                NullPointerException.class,
                                () -> {
                                        provider.getPrivateKey();
                                });
                verify(mockSessionKeySupplier).getKeyPair();
        }
}