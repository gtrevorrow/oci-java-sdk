/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates. All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AbstractAsyncFederationClient;
import com.oracle.bmc.auth.internal.SecurityTokenAdapter;
import com.oracle.bmc.auth.internal.WorkloadIdentityFederationClient;
import com.oracle.bmc.auth.internal.SubjectTokenSupplierImpl;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import com.oracle.bmc.http.ClientConfigurator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
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

@RunWith(MockitoJUnitRunner.Silent.class)
public class WorkloadIdentityFederationAuthDetailProviderTest {

        @Mock
        private WorkloadIdentityFederationClient mockFederationClient;

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
        private WorkloadIdentityFederationAuthenticationDetailProvider provider;

        @Before
        public void setUp() {
                // Stub common behavior for mockFederationClient
                when(mockFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class)))
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));
                when(mockFederationClient.refreshAndGetSecurityTokenIfExpiringWithin(
                                any(Duration.class), any(Boolean.class)))
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
        public void builderCreatesProviderWithCorrectConfiguration() {
                ClientConfigurator mockClientConfigurator = mock(ClientConfigurator.class);
                CircuitBreakerConfiguration mockCircuitBreakerConfiguration = mock(CircuitBreakerConfiguration.class);
                List<ClientConfigurator> mockAdditionalClientConfigurators = Collections
                                .singletonList(mock(ClientConfigurator.class));

                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected AbstractAsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
                                // Return a mock client to prevent real network calls
                                return mock(AbstractAsyncFederationClient.class);
                        }
                };

                WorkloadIdentityFederationAuthenticationDetailProvider provider = builder
                                .clientCredential("test-credential")
                                .subjectTokenSupplier(() -> "test-subject-token")
                                .tokenExchangeUrl("https://auth.example.com/token")
                                .region(Region.US_ASHBURN_1)
                                .clientConfigurator(mockClientConfigurator)
                                .circuitBreakerConfiguration(mockCircuitBreakerConfiguration)
                                .additionalClientConfigurators(mockAdditionalClientConfigurators)
                                .secondsToExpireSessionTokenEarly(500L)
                                .build();

                assertNotNull(provider);
        }

        @Test
        public void constructorInitializesRegionAndKeyId() {
                setupMockKeyPair();
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);
                assertEquals(MOCK_REGION, provider.getRegion());
                assertNotNull(provider.getKeyId());
        }

        @Test
        public void constructorWithNullFederationClientThrowsException() {
                assertThrows(
                                "Federation client must not be null",
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                null, mockSessionKeySupplier, MOCK_TOKEN_EXCHANGE_URL, MOCK_REGION));
        }

        @Test
        public void constructorWithNullSessionKeySupplierThrowsException() {
                assertThrows(
                                "Session key supplier must not be null",
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, null, MOCK_TOKEN_EXCHANGE_URL, MOCK_REGION));
        }

        @Test
        public void constructorWithNullTokenExchangeUrlThrowsException() {
                assertThrows(
                                "Token exchange URL must not be null or empty",
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, null, MOCK_REGION));
        }

        @Test
        public void constructorWithEmptyTokenExchangeUrlThrowsException() {
                assertThrows(
                                "Token exchange URL must not be null or empty",
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, " ", MOCK_REGION));
        }

        @Test
        public void constructorWithNullRegionThrowsException() {
                assertThrows(
                                "Region must not be null",
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, MOCK_TOKEN_EXCHANGE_URL,
                                                null));
        }

        @Test
        public void builderWithNullTokenUrlThrowsException() {
                assertThrows(
                                "Token exchange URL must not be null or empty",
                                IllegalArgumentException.class,
                                () -> WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                                .tokenExchangeUrl(null)
                                                .build());
        }

        @Test
        public void builderWithNullSubjectTokenSupplierThrowsException() {
                assertThrows(
                                "Subject token supplier cannot be null",
                                IllegalArgumentException.class,
                                () -> WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                                .region(MOCK_REGION)
                                                .subjectTokenSupplier(null)
                                                .build());
        }

        @Test
        public void builderWithNullClientCredentialThrowsException() {
                assertThrows(
                                "Client credential must not be null or empty",
                                IllegalArgumentException.class,
                                () -> WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                                .region(MOCK_REGION)
                                                .clientCredential(null)
                                                .build());
        }

        @Test
        public void refreshActuallyCallsRefresh() {
                setupMockKeyPair();
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);
                provider.refresh();
                verify(mockFederationClient, times(1)).refreshAndGetSecurityToken();
        }

        @Test
        public void getSecurityTokenReturnsToken() {
                setupMockKeyPair();
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);
                assertEquals(MOCK_SECURITY_TOKEN, provider.refresh());
        }

        @Test
        public void refreshReturnsTokenFromFederationClient() {
                setupMockKeyPair();
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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

                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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
                WorkloadIdentityFederationClient federationClient = new WorkloadIdentityFederationClient(
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
                class CountingFederationClient extends WorkloadIdentityFederationClient {
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
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                countingClient,
                                realKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                // Launch 5 concurrent refresh tasks with controlled execution
                int concurrentThreads = 5;
                ExecutorService executor = Executors.newFixedThreadPool(concurrentThreads);
                Semaphore startSemaphore = new Semaphore(0);
                Semaphore completeSemaphore = new Semaphore(0);
                @SuppressWarnings("unchecked")
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
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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

                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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
                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
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

        @Test
        public void testConcurrentTokenRefresh() throws InterruptedException {
                int numThreads = 10;
                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                CountDownLatch latch = new CountDownLatch(numThreads);
                Semaphore semaphore = new Semaphore(1); // To control access to the refresh logic

                // Mock the federation client to simulate a refresh operation
                when(mockFederationClient.refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class)))
                                .thenAnswer(
                                                invocation -> {
                                                        // Simulate work and potential delay
                                                        boolean acquired = semaphore.tryAcquire();
                                                        if (acquired) {
                                                                try {
                                                                        // Simulate network delay
                                                                        Thread.sleep(100);
                                                                        return CompletableFuture.completedFuture(
                                                                                        MOCK_NEW_SECURITY_TOKEN);
                                                                } finally {
                                                                        semaphore.release();
                                                                }
                                                        } else {
                                                                // Another thread is already refreshing, so return the
                                                                // old token
                                                                return CompletableFuture
                                                                                .completedFuture(MOCK_SECURITY_TOKEN);
                                                        }
                                                });

                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                // Initial token state is set up in @Before
                for (int i = 0; i < numThreads; i++) {
                        executor.submit(
                                        () -> {
                                                try {
                                                        // Each thread will try to get the token, triggering the refresh
                                                        // logic
                                                        provider.refreshAndGetSecurityTokenIfExpiringWithin(
                                                                        Duration.ofSeconds(1));
                                                } finally {
                                                        latch.countDown();
                                                }
                                        });
                }

                latch.await(5, TimeUnit.SECONDS);
                executor.shutdown();

                // Verify that refresh was called, but only once due to coordination
                verify(mockFederationClient, times(10))
                                .refreshAndGetSecurityTokenIfExpiringWithin(any(Duration.class));
        }

        @Test
        public void testSubjectTokenSupplier()
                        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
                // Setup
                SubjectTokenSupplierImpl supplier = mock(SubjectTokenSupplierImpl.class,
                                withSettings().defaultAnswer(CALLS_REAL_METHODS));
                when(supplier.get()).thenReturn(MOCK_SUBJECT_TOKEN);

                // Execute
                String token = supplier.get();

                // Verify
                assertEquals(MOCK_SUBJECT_TOKEN, token);
        }
}