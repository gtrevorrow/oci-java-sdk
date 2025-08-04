/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

import com.oracle.bmc.auth.internal.AuthUtils;

/**
 * A standalone CachingSessionKeySupplier implementation that provides caching functionality
 * for session keys while maintaining complete independence and modularity.
 * <p>
 * This implementation decouples the caching of session keys from AbstractRequestingAuthenticationDetailsProvider,
 * allowing any authentication provider to use caching functionality without creating dependencies
 * on other authentication provider classes.
 * <p>
 * This implementation wraps another SessionKeySupplier and caches the private key bytes
 * to avoid repeated expensive serialization operations. It uses thread-safe double-checked
 * locking for optimal performance in concurrent environments.
 */
public class CachingSessionKeySupplier implements SessionKeySupplier {
    private final SessionKeySupplier delegate;
    private volatile RSAPrivateKey lastPrivateKey = null;
    private volatile byte[] privateKeyBytes = null;

    /**
     * Creates a new CachingSessionKeySupplier that wraps the provided delegate.
     *
     * @param delegate the SessionKeySupplier to wrap and cache results for
     * @throws IllegalArgumentException if delegate is null
     */
    public CachingSessionKeySupplier(final SessionKeySupplier delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("Delegate SessionKeySupplier must not be null");
        }
        this.delegate = delegate;
    }

    @Override
    public KeyPair getKeyPair() {
        return delegate.getKeyPair();
    }

    @Override
    public synchronized void refreshKeys() {
        delegate.refreshKeys();
    }

    /**
     * Returns the cached private key bytes, updating the cache if the key has changed.
     * Uses double-checked locking pattern for thread safety and performance.
     *
     * @return the private key as byte array
     */
    public byte[] getPrivateKeyBytes() {
        RSAPrivateKey currentPrivateKey = (RSAPrivateKey) this.getKeyPair().getPrivate();

        // First check without synchronization for performance
        if (currentPrivateKey != lastPrivateKey) {
            synchronized (this) {
                // Double-checked locking: verify the condition again inside the synchronized block
                if (currentPrivateKey != lastPrivateKey) {
                    lastPrivateKey = currentPrivateKey;
                    this.privateKeyBytes = AuthUtils.toByteArrayFromRSAPrivateKey(currentPrivateKey);
                }
            }
        }
        return this.privateKeyBytes;
    }
}
