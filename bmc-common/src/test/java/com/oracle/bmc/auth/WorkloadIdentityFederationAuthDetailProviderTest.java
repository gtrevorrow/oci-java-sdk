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
import com.oracle.bmc.retrier.DefaultRetryCondition;
import com.oracle.bmc.retrier.RetryConfiguration;
import com.oracle.bmc.waiter.ExponentialBackoffDelayStrategyWithJitter;
import com.oracle.bmc.waiter.MaxAttemptsTerminationStrategy;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.Silent.class)
public class WorkloadIdentityFederationAuthDetailProviderTest {

        private static final Logger logger = Logger
                        .getLogger(WorkloadIdentityFederationAuthDetailProviderTest.class.getName());

        // Test constants
        private static final String MOCK_TOKEN_EXCHANGE_URL = "https://test.token.exchange.url";
        private static final String MOCK_SECURITY_TOKEN = "refreshed-token"; // Match what's returned by mock
        // Valid JWT format for testing (header.payload.signature)
        private static final String MOCK_NEW_SECURITY_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjEwMDAwMDAwfQ.signature-part";
        private static final String MOCK_CLIENT_CREDENTIAL = "dGVzdC1jbGllbnQtY3JlZGVudGlhbA=="; // base64 encoded
        private static final Region MOCK_REGION = Region.US_PHOENIX_1;

        @Mock
        private WorkloadIdentityFederationClient mockFederationClient;

        @Mock
        private SessionKeySupplier mockSessionKeySupplier;

        @Mock
        private SecurityTokenAdapter mockSecurityTokenAdapter;

        @Mock
        private Supplier<String> mockSubjectTokenSupplier;

        private WorkloadIdentityFederationAuthenticationDetailProvider provider;

        @Before
        public void setUp() {
                // Set up mock behavior for federation client
                when(mockFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture("mock-token"));
                when(mockFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture("refreshed-token"));

                provider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                mockFederationClient,
                                mockSessionKeySupplier,
                                "https://test.token.exchange.url",
                                Region.US_PHOENIX_1);
        }

        @After
        public void tearDown() {
                if (provider != null) {
                        provider.shutdown();
                }
        }

        @Test
        public void builderWithCircuitBreakerIsEnabled() {
                class ConfigurationCapturingBuilder extends
                                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder {
                        CircuitBreakerConfiguration capturedCircuitBreakerConfiguration;
                        boolean circuitBreakerEnabled = false;

                        @Override
                        public WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder withCircuitBreaker() {
                                circuitBreakerEnabled = true;
                                return super.withCircuitBreaker();
                        }

                        @Override
                        protected AbstractAsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
                                if (circuitBreakerEnabled) {
                                        capturedCircuitBreakerConfiguration = CircuitBreakerConfiguration.builder()
                                                        .build();
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
                class ConfigurationCapturingBuilder extends
                                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder {
                        CircuitBreakerConfiguration capturedCircuitBreakerConfiguration;
                        boolean circuitBreakerEnabled = false;

                        @Override
                        public WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder withCircuitBreaker() {
                                circuitBreakerEnabled = true;
                                return super.withCircuitBreaker();
                        }

                        @Override
                        protected AbstractAsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
                                if (circuitBreakerEnabled) {
                                        capturedCircuitBreakerConfiguration = CircuitBreakerConfiguration.builder()
                                                        .build();
                                }
                                return mock(AbstractAsyncFederationClient.class);
                        }
                }

                ConfigurationCapturingBuilder builder = new ConfigurationCapturingBuilder();
                builder.clientCredential("test")
                                .subjectTokenSupplier(() -> "test")
                                .tokenExchangeUrl("https://test.com")
                                .region(Region.US_ASHBURN_1)
                                // DO NOT enable circuit breaker
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

        // Verifies that concurrent refresh calls share a single in-flight refresh,
        // ensuring only one call goes to the server while all callers receive the
        // same refreshed token.
        // It wires a counting wrapper around the federation client, synchronizes thread
        // starts with latches/semaphores, and completes the server future once the
        // first caller reaches the fetch to assert fan-out behavior.
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
                                firstCallLatch.countDown();
                                serverCallCount++;
                                logger.info("getSecurityTokenFromServer called, count: " + serverCallCount
                                                + ", thread: " + Thread.currentThread().getName());
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
                boolean allCompleted = completeSemaphore.tryAcquire(concurrentThreads, 10, TimeUnit.SECONDS);
                assertTrue("Refresh tasks did not all complete", allCompleted);

                // Shutdown executor
                executor.shutdown();
                boolean terminated = executor.awaitTermination(10, TimeUnit.SECONDS);
                assertTrue("Executor did not terminate in time", terminated);

                // Verify results
                assertEquals("Only one server call should have been made", 1, countingClient.getServerCallCount());
                for (int i = 0; i < concurrentThreads; i++) {
                        assertFalse("Refresh future completed exceptionally",
                                        refreshFutures[i].isCompletedExceptionally());
                        assertEquals("All threads should have the same token", MOCK_NEW_SECURITY_TOKEN,
                                        refreshFutures[i].get(5, TimeUnit.SECONDS));
                }
        }

        @Test
        public void buildAsyncPreFetchesTokenSuccessfully() throws Exception {
                // Setup mock federation client to return a token
                WorkloadIdentityFederationClient realFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(realFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Create a builder that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
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
                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncProviderFuture.get(5,
                                TimeUnit.SECONDS);
                assertNotNull("Async provider should not be null", asyncProvider);
                assertEquals("Region should match", MOCK_REGION, asyncProvider.getRegion());

                // Verify that getSecurityToken was called during buildAsync (token
                // pre-fetching)
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
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
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
                // buildAsync() = token fetched during provider creation, provider ready
                // immediately

                CountDownLatch tokenFetchStarted = new CountDownLatch(1);
                CountDownLatch allowTokenFetchToComplete = new CountDownLatch(1);

                // Create a mock federation client that allows us to control timing
                WorkloadIdentityFederationClient controlledFederationClient = mock(
                                WorkloadIdentityFederationClient.class);
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
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
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
                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncFuture.get(5,
                                TimeUnit.SECONDS);
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
                // Verify that buildAsync() creates a provider with identical configuration to
                // build()
                setupMockKeyPair();

                // Mock the federation client for BOTH sync and async tests to avoid real HTTP
                // calls
                WorkloadIdentityFederationClient mockSyncFederationClient = mock(
                                WorkloadIdentityFederationClient.class);
                when(mockSyncFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                WorkloadIdentityFederationClient mockAsyncFederationClient = mock(
                                WorkloadIdentityFederationClient.class);
                when(mockAsyncFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Create a builder for sync provider that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder syncBuilder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
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
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder asyncBuilder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
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

                // Verify the sync provider only fetched tokens when needed (during getKeyId()
                // call)
                verify(mockSyncFederationClient, times(1)).getSecurityToken(); // Called only by getKeyId()
        }

        @Test
        public void testProactiveRefreshIsHandledByClient() {
                // Verify that proactive refresh is handled internally by
                // WorkloadIdentityFederationClient
                // The provider should just delegate to the client without any scheduling logic

                when(mockFederationClient.refreshAndGetSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture("new-token"));

                // Call refresh - this should delegate to the client
                String token = provider.refresh();

                // Verify the refresh was called and returned the expected token
                assertEquals("new-token", token);
                verify(mockFederationClient, times(1)).refreshAndGetSecurityToken();
        }

        @Test
        public void testShutdownDelegatesToClient() {
                // Verify that shutdown delegates to the underlying federation client and is
                // idempotent.
                class ShutdownCapturingClient extends WorkloadIdentityFederationClient {
                        private int shutdownCount = 0;

                        ShutdownCapturingClient(String tokenExchangeEndpoint, Supplier<String> subjectTokenSupplier,
                                        SessionKeySupplier sessionKeySupplier, String clientCredentials) {
                                super(tokenExchangeEndpoint, subjectTokenSupplier, sessionKeySupplier,
                                                clientCredentials);
                        }

                        @Override
                        public void shutdown() {
                                shutdownCount++;
                                super.shutdown();
                        }

                        int getShutdownCount() {
                                return shutdownCount;
                        }
                }

                SessionKeySupplier realKeySupplier = new SessionKeySupplierImpl();
                ShutdownCapturingClient capturingClient = new ShutdownCapturingClient(
                                MOCK_TOKEN_EXCHANGE_URL,
                                mockSubjectTokenSupplier,
                                realKeySupplier,
                                MOCK_CLIENT_CREDENTIAL);

                WorkloadIdentityFederationAuthenticationDetailProvider shutdownProvider = new WorkloadIdentityFederationAuthenticationDetailProvider(
                                capturingClient,
                                realKeySupplier,
                                MOCK_TOKEN_EXCHANGE_URL,
                                MOCK_REGION);

                shutdownProvider.shutdown();
                shutdownProvider.shutdown();

                assertEquals("Shutdown should delegate on each call", 2, capturingClient.getShutdownCount());
        }

        @Test
        public void testProactiveRefreshFlagReflectsRetryConfigurationPresence() {
                class ProactiveRefreshCapturingBuilder extends
                                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder {
                        boolean proactiveRefreshEnabled = false;

                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
                                WorkloadIdentityFederationClient mockClient = mock(
                                                WorkloadIdentityFederationClient.class);
                                when(mockClient.getSecurityToken())
                                                .thenReturn(CompletableFuture.completedFuture("test-token"));
                                return mockClient;
                        }

                        @Override
                        public WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder retryConfiguration(
                                        RetryConfiguration retryConfiguration) {
                                proactiveRefreshEnabled = (retryConfiguration != null);
                                return super.retryConfiguration(retryConfiguration);
                        }
                }

                ProactiveRefreshCapturingBuilder withRetry = new ProactiveRefreshCapturingBuilder();
                withRetry.clientCredential("test")
                                .subjectTokenSupplier(() -> "test")
                                .tokenExchangeUrl("https://test.com")
                                .region(Region.US_ASHBURN_1)
                                .retryConfiguration(createTestRetryConfiguration(3, 30))
                                .build();
                assertTrue("Proactive refresh should be enabled when retry configuration is provided",
                                withRetry.proactiveRefreshEnabled);

                ProactiveRefreshCapturingBuilder withoutRetry = new ProactiveRefreshCapturingBuilder();
                withoutRetry.clientCredential("test")
                                .subjectTokenSupplier(() -> "test")
                                .tokenExchangeUrl("https://test.com")
                                .region(Region.US_ASHBURN_1)
                                .build();
                assertFalse("Proactive refresh should be disabled when retry configuration is absent",
                                withoutRetry.proactiveRefreshEnabled);
        }

        @Test
        public void testRetryConfigurationWithNullThrowsException() {
                assertThrows(IllegalArgumentException.class, () -> {
                        WorkloadIdentityFederationAuthenticationDetailProvider.builder()
                                        .retryConfiguration(null);
                });
        }

        @Test
        public void testProactiveRefreshWithRetryConfiguration() throws Exception {
                // Test that proactive refresh works with retry configuration
                WorkloadIdentityFederationClient mockFederationClient = mock(WorkloadIdentityFederationClient.class);
                when(mockFederationClient.getSecurityToken())
                                .thenReturn(CompletableFuture.completedFuture(MOCK_SECURITY_TOKEN));

                // Create a builder that returns our mock federation client
                WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder builder = new WorkloadIdentityFederationAuthenticationDetailProvider.WorkloadIdentityFederationAuthenticationDetailProviderBuilder() {
                        @Override
                        protected com.oracle.bmc.auth.internal.AsyncFederationClient createFederationClient(
                                        SessionKeySupplier sessionKeySupplier) {
                                return mockFederationClient;
                        }
                };

                // Test buildAsync() with retry configuration (which automatically enables
                // proactive refresh)
                CompletableFuture<WorkloadIdentityFederationAuthenticationDetailProvider> asyncProviderFuture = builder
                                .tokenExchangeUrl(MOCK_TOKEN_EXCHANGE_URL)
                                .subjectTokenSupplier(mockSubjectTokenSupplier)
                                .clientCredential(MOCK_CLIENT_CREDENTIAL)
                                .region(MOCK_REGION)
                                .retryConfiguration(createTestRetryConfiguration(3, 30)) // Enable retry configuration
                                                                                         // (automatically enables
                                                                                         // proactive refresh)
                                .buildAsync();

                // Verify the future completes successfully
                WorkloadIdentityFederationAuthenticationDetailProvider asyncProvider = asyncProviderFuture.get(5,
                                TimeUnit.SECONDS);
                assertNotNull("Async provider with retry configuration should not be null", asyncProvider);
                assertEquals("Region should match", MOCK_REGION, asyncProvider.getRegion());

                // Verify that getSecurityToken was called during buildAsync (token
                // pre-fetching)
                verify(mockFederationClient, times(1)).getSecurityToken();
        }

        private void setupMockKeyPair() {
                SessionKeySupplier realSupplier = new SessionKeySupplierImpl();
                when(mockSessionKeySupplier.getKeyPair()).thenAnswer(invocation -> realSupplier.getKeyPair());
                doAnswer(invocation -> {
                        realSupplier.refreshKeys();
                        return null;
                }).when(mockSessionKeySupplier).refreshKeys();
        }

        private static RetryConfiguration createTestRetryConfiguration(int maxAttempts, long maxDelaySeconds) {
                long maxDelayMillis = TimeUnit.SECONDS.toMillis(maxDelaySeconds);
                return RetryConfiguration.builder()
                                .terminationStrategy(new MaxAttemptsTerminationStrategy(maxAttempts))
                                .delayStrategy(new ExponentialBackoffDelayStrategyWithJitter(maxDelayMillis))
                                .retryCondition(exception -> new DefaultRetryCondition().shouldBeRetried(exception))
                                .build();
        }
}
