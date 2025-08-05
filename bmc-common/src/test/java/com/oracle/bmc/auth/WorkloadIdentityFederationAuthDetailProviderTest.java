/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates. All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.internal.AbstractAsyncFederationClient;
import com.oracle.bmc.auth.internal.SecurityTokenAdapter;
import com.oracle.bmc.auth.internal.WorkloadIdentityFederationClient;
import com.oracle.bmc.circuitbreaker.CircuitBreakerConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.Silent.class)
public class WorkloadIdentityFederationAuthDetailProviderTest {

        private static final Logger logger = Logger.getLogger(WorkloadIdentityFederationAuthDetailProviderTest.class.getName());

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
        public void builderWithCircuitBreakerIsEnabled() {
                class ConfigurationCapturingBuilder extends WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder {
                        CircuitBreakerConfiguration capturedCircuitBreakerConfiguration;
                        boolean circuitBreakerEnabled = false;

                        @Override
                        public WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder withCircuitBreaker() {
                                circuitBreakerEnabled = true;
                                return super.withCircuitBreaker();
                        }

                        @Override
                        protected AbstractAsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                if (circuitBreakerEnabled) {
                                        capturedCircuitBreakerConfiguration = CircuitBreakerConfiguration.builder().build();
                                }
                                return mock(AbstractAsyncFederationClient.class);
                        }
                }

                ConfigurationCapturingBuilder builder = new ConfigurationCapturingBuilder();
                builder.clientCredential("test")
                                .subjectTokenSupplier(() -> "test")
                                .tokenExchangeUrl("https://test.com")
                                .region(Region.US_ASHBURN_1)
                                .withCircuitBreaker() // Enable it
                                .build();

                assertNotNull(builder.capturedCircuitBreakerConfiguration);
        }

        @Test
        public void builderWithoutCircuitBreakerIsDefault() {
                class ConfigurationCapturingBuilder extends WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder {
                        CircuitBreakerConfiguration capturedCircuitBreakerConfiguration;
                        boolean circuitBreakerEnabled = false;

                        @Override
                        public WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder withCircuitBreaker() {
                                circuitBreakerEnabled = true;
                                return super.withCircuitBreaker();
                        }

                        @Override
                        protected AbstractAsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                if (circuitBreakerEnabled) {
                                        capturedCircuitBreakerConfiguration = CircuitBreakerConfiguration.builder().build();
                                }
                                return mock(AbstractAsyncFederationClient.class);
                        }
                }

                ConfigurationCapturingBuilder builder = new ConfigurationCapturingBuilder();
                builder.clientCredential("test")
                                .subjectTokenSupplier(() -> "test")
                                .tokenExchangeUrl("https://test.com")
                                .region(Region.US_ASHBURN_1)
                                // DO NOT enable it
                                .build();

                assertNull(builder.capturedCircuitBreakerConfiguration);
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
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                null, mockSessionKeySupplier, MOCK_TOKEN_EXCHANGE_URL, MOCK_REGION));
        }

        @Test
        public void constructorWithNullSessionKeySupplierThrowsException() {
                assertThrows(
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, null, MOCK_TOKEN_EXCHANGE_URL, MOCK_REGION));
        }

        @Test
        public void constructorWithNullTokenExchangeUrlThrowsException() {
                assertThrows(
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, null, MOCK_REGION));
        }

        @Test
        public void constructorWithEmptyTokenExchangeUrlThrowsException() {
                assertThrows(
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, " ", MOCK_REGION));
        }

        @Test
        public void constructorWithNullRegionThrowsException() {
                assertThrows(
                                IllegalArgumentException.class,
                                () -> new WorkloadIdentityFederationAuthenticationDetailProvider(
                                                mockFederationClient, mockSessionKeySupplier, MOCK_TOKEN_EXCHANGE_URL,
                                                null));
        }

        @Test
        public void builderWithNullTokenUrlThrowsException() {
                assertThrows(
                                IllegalArgumentException.class,
                                () -> WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                                .tokenExchangeUrl(null)
                                                .build());
        }

        @Test
        public void builderWithNullSubjectTokenSupplierThrowsException() {
                assertThrows(
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
                                logger.info("Created CountingFederationClient: " + System.identityHashCode(this));
                                this.serverFuture = serverFuture;
                        }

                        @Override
                        public CompletableFuture<SecurityTokenAdapter> getSecurityTokenFromServer() {
                                serverCallCount++;
                                logger.info("getSecurityTokenFromServer called, count: " + serverCallCount
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
                                logger.info("Thread " + threadIndex + " starting refresh");
                                startSemaphore.release(); // Signal thread has started
                                try {
                                        String result = provider.refresh(); // Blocks on .get()
                                        logger.info("Thread " + threadIndex + " completed refresh, result: " + result);
                                        completeSemaphore.release();
                                        return result;
                                } catch (Exception e) {
                                        logger.severe("Thread " + threadIndex + " refresh failed: " + e.getMessage());
                                        throw e;
                                }
                        }, executor);
                }

                // Wait for all threads to start
                logger.info("Waiting for all threads to start");
                startSemaphore.acquire(concurrentThreads);

                // Wait for the first call to getSecurityTokenFromServer
                logger.info("Waiting for first call to getSecurityTokenFromServer");
                countingClient.getFirstCallLatch().await();

                // Complete the server future
                logger.info("Completing server future");
                SecurityTokenAdapter newTokenAdapter = new SecurityTokenAdapter(MOCK_NEW_SECURITY_TOKEN,
                                realKeySupplier);
                serverFuture.complete(newTokenAdapter);

                // Wait for all threads to complete
                logger.info("Waiting for all threads to complete");
                completeSemaphore.acquire(concurrentThreads);

                // Shutdown executor
                executor.shutdown();
                boolean terminated = executor.awaitTermination(10, TimeUnit.SECONDS);
                if (!terminated) {
                        logger.warning("Executor did not terminate in the specified time.");
                        // Optionally, you can force shutdown or handle it according to your requirements
                }

                // Verify results
                assertEquals("Only one server call should have been made", 1, countingClient.getServerCallCount());
                for (int i = 0; i < concurrentThreads; i++) {
                        assertEquals("All threads should have the same token", MOCK_NEW_SECURITY_TOKEN,
                                        refreshFutures[i].get());
                }
        }

        @Test
        public void buildAsyncPreFetchesTokenSuccessfully() throws Exception {
                // Setup mock federation client to return a token
                WorkloadIdentityFederationClient realFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(realFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Create a builder that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder =
                        new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                                @Override
                                protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                        return realFederationClient;
                                }
                        };

                // Test buildAsync() completes successfully
                CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> asyncProviderFuture = builder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .buildAsync();

                // Verify the future completes and returns a valid provider
                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncProviderFuture.get(5, TimeUnit.SECONDS);
                assertNotNull("Async provider should not be null", asyncProvider);
                assertEquals("Region should match", MOCK_REGION, asyncProvider.getRegion());

                // Verify that getSecurityToken was called during buildAsync (token pre-fetching)
                verify(realFederationClient, times(1)).getSecurityToken();
        }

        @Test
        public void buildAsyncHandlesTokenFetchFailure() throws Exception {
                // Setup mock federation client to fail token fetch
                WorkloadIdentityFederationClient realFederationClient = mock(WorkloadIdentityFederationClient.class);
                CompletableFuture<String> failedTokenFuture = new CompletableFuture<>();
                failedTokenFuture.completeExceptionally(new RuntimeException("Token fetch failed"));
                when(realFederationClient.getSecurityToken()).thenReturn(failedTokenFuture);

                // Create a builder that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder =
                        new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                                @Override
                                protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                        return realFederationClient;
                                }
                        };

                // Test buildAsync() fails appropriately
                CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> asyncProviderFuture = builder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .buildAsync();

                // Verify the future completes exceptionally
                try {
                        asyncProviderFuture.get(5, TimeUnit.SECONDS);
                        fail("Expected CompletionException due to token fetch failure");
                } catch (java.util.concurrent.ExecutionException e) {
                        assertEquals("Token fetch failed", e.getCause().getMessage());
                }

                // Verify that getSecurityToken was attempted
                verify(realFederationClient, times(1)).getSecurityToken();
        }

        @Test
        public void buildAsyncVsSyncBehaviorComparison() throws Exception {
                // This test demonstrates the key difference between build() and buildAsync()
                // build() = provider created immediately, token fetched on first use
                // buildAsync() = token fetched during provider creation, provider ready immediately

                CountDownLatch tokenFetchStarted = new CountDownLatch(1);
                CountDownLatch allowTokenFetchToComplete = new CountDownLatch(1);

                // Create a mock federation client that allows us to control timing
                WorkloadIdentityFederationClient controlledFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(controlledFederationClient.getSecurityToken()).thenAnswer(invocation -> {
                        logger.info("Token fetch started");
                        tokenFetchStarted.countDown();
                        return CompletableFuture.supplyAsync(() -> {
                                try {
                                        allowTokenFetchToComplete.await(10, TimeUnit.SECONDS);
                                        logger.info("Token fetch completed");
                                        return MOCK_SECURITY_TOKEN;
                                } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                        throw new RuntimeException("Token fetch interrupted", e);
                                }
                        });
                });

                // Create a builder that returns our controlled federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder =
                        new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                                @Override
                                protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                        return controlledFederationClient;
                                }
                        };

                // Test buildAsync() - should trigger token fetch immediately
                logger.info("Starting buildAsync() test");
                CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> asyncFuture = builder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .buildAsync();

                // Verify token fetch was started immediately by buildAsync()
                boolean tokenFetchStartedByBuildAsync = tokenFetchStarted.await(5, TimeUnit.SECONDS);
                assertEquals("buildAsync() should trigger immediate token fetch", true, tokenFetchStartedByBuildAsync);

                // Allow token fetch to complete
                allowTokenFetchToComplete.countDown();

                // Verify buildAsync() completes successfully
                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncFuture.get(5, TimeUnit.SECONDS);
                assertNotNull("Async provider should be created successfully", asyncProvider);

                // Verify getSecurityToken was called during buildAsync (pre-fetching behavior)
                verify(controlledFederationClient, times(1)).getSecurityToken();

                logger.info("buildAsync() test completed successfully");
        }

        @Test
        public void buildAsyncWithMissingRequiredFieldsThrowsException() {
                // Test that buildAsync() validates required fields just like build()

                // Missing token exchange URL
                assertThrows(IllegalArgumentException.class, () -> {
                        WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                        .subjectTokenSupplier(mockSubjectTokenSupplier)
                                        .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                        .region(MOCK_REGION)
                                        .buildAsync();
                });

                // Missing subject token supplier
                assertThrows(IllegalArgumentException.class, () -> {
                        WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                        .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                        .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                        .region(MOCK_REGION)
                                        .buildAsync();
                });

                // Missing client credential
                assertThrows(IllegalArgumentException.class, () -> {
                        WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                        .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                        .subjectTokenSupplier(mockSubjectTokenSupplier)
                                        .region(MOCK_REGION)
                                        .buildAsync();
                });

                // Missing region
                assertThrows(IllegalArgumentException.class, () -> {
                        WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                        .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                        .subjectTokenSupplier(mockSubjectTokenSupplier)
                                        .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                        .buildAsync();
                });
        }

        @Test
        public void buildAsyncReturnsProviderWithSameConfigurationAsBuild() throws Exception {
                // Verify that buildAsync() creates a provider with identical configuration to build()
                setupMockKeyPair();

                // Mock the federation client for BOTH sync and async tests to avoid real HTTP calls
                WorkloadIdentityFederationClient mockSyncFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(mockSyncFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                WorkloadIdentityFederationClient mockAsyncFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(mockAsyncFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Create a builder for sync provider that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder syncBuilder =
                        new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                                @Override
                                protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                        return mockSyncFederationClient;
                                }
                        };

                // Create sync provider with mocked federation client
                WorkloadIdentityFederationAuthenticationDetailProvider syncProvider = syncBuilder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .secondsToExpireSessionTokenEarly(300L)
                                .build();

                // Create a builder for async provider that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder asyncBuilder =
                        new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                                @Override
                                protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(SessionKeySupplier sessionKeySupplier) {
                                        return mockAsyncFederationClient;
                                }
                        };

                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncBuilder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .secondsToExpireSessionTokenEarly(300L)
                                .buildAsync()
                                .get(5, TimeUnit.SECONDS);

                // Verify both providers have the same configuration
                assertEquals("Both providers should have the same region",
                        syncProvider.getRegion(), asyncProvider.getRegion());
                assertNotNull("Both providers should have non-null key IDs", syncProvider.getKeyId());
                assertNotNull("Both providers should have non-null key IDs", asyncProvider.getKeyId());
                assertNotNull("Both providers should have private keys", syncProvider.getPrivateKey());
                assertNotNull("Both providers should have private keys", asyncProvider.getPrivateKey());

                // Verify the async provider had its token pre-fetched during buildAsync()
                // AND called again during getKeyId() - so expect 2 calls total
                verify(mockAsyncFederationClient, times(2)).getSecurityToken();

                // Verify the sync provider only fetched tokens when needed (during getKeyId() call)
                verify(mockSyncFederationClient, times(1)).getSecurityToken(); // Called only by getKeyId()
        }
}

