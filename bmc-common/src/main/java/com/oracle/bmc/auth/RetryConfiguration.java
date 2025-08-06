/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

/**
 * Configuration for retry behavior when proactive token refresh fails.
 * This configuration controls how the authentication provider handles transient failures
 * during background token refresh operations.
 */
public class RetryConfiguration {

    private final boolean enableRetryOnFailure;
    private final int maxRetryAttempts;
    private final long retryDelaySeconds;

    // Static constants for common configurations
    public static final RetryConfiguration BASIC = new RetryConfiguration(true, 3, 30);
    public static final RetryConfiguration CONSERVATIVE = new RetryConfiguration(true, 3, 60);
    public static final RetryConfiguration AGGRESSIVE = new RetryConfiguration(true, 5, 30);

    /**
     * Creates a new retry configuration.
     *
     * @param enableRetryOnFailure whether to enable retries on failure
     * @param maxRetryAttempts maximum number of retry attempts (must be >= 0)
     * @param retryDelaySeconds base delay in seconds between retries (must be > 0)
     */
    public RetryConfiguration(boolean enableRetryOnFailure, int maxRetryAttempts, long retryDelaySeconds) {
        if (maxRetryAttempts < 0) {
            throw new IllegalArgumentException("maxRetryAttempts must be >= 0");
        }
        if (retryDelaySeconds <= 0) {
            throw new IllegalArgumentException("retryDelaySeconds must be > 0");
        }

        this.enableRetryOnFailure = enableRetryOnFailure;
        this.maxRetryAttempts = maxRetryAttempts;
        this.retryDelaySeconds = retryDelaySeconds;
    }

    /**
     * Returns whether retries are enabled on failure.
     *
     * @return true if retries are enabled, false otherwise
     */
    public boolean isEnableRetryOnFailure() {
        return enableRetryOnFailure;
    }

    /**
     * Returns the maximum number of retry attempts.
     *
     * @return maximum retry attempts
     */
    public int getMaxRetryAttempts() {
        return maxRetryAttempts;
    }

    /**
     * Returns the base delay in seconds between retry attempts.
     * The actual delay uses exponential backoff based on this value.
     *
     * @return base retry delay in seconds
     */
    public long getRetryDelaySeconds() {
        return retryDelaySeconds;
    }


    /**
     * Creates a custom retry configuration.
     *
     * @param maxRetryAttempts maximum number of retry attempts
     * @param retryDelaySeconds base delay in seconds between retries
     * @return custom retry configuration
     */
    public static RetryConfiguration custom(int maxRetryAttempts, long retryDelaySeconds) {
        return new RetryConfiguration(true, maxRetryAttempts, retryDelaySeconds);
    }

    @Override
    public String toString() {
        return String.format("RetryConfiguration{enableRetryOnFailure=%s, maxRetryAttempts=%d, retryDelaySeconds=%d}",
            enableRetryOnFailure, maxRetryAttempts, retryDelaySeconds);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RetryConfiguration that = (RetryConfiguration) o;
        return enableRetryOnFailure == that.enableRetryOnFailure &&
               maxRetryAttempts == that.maxRetryAttempts &&
               retryDelaySeconds == that.retryDelaySeconds;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(enableRetryOnFailure, maxRetryAttempts, retryDelaySeconds);
    }
}
