package com.oracle.bmc.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * This is a helper class to generate in-memory temporary session keys.
 *
 * <p>
 * The thread safety of this class is ensured through the Caching class above
 * which
 * synchronizes on all methods.
 *
 * <p>
 * The class is implemented in a lazy way to avoid generating the key if it is
 * not needed or
 * if refresh is immediately called.
 */
class SessionKeySupplierImpl implements SessionKeySupplier {
    private static final KeyPairGenerator GENERATOR;
    private KeyPair keyPair = null;

    static {
        try {
            GENERATOR = KeyPairGenerator.getInstance("RSA");
            GENERATOR.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e.getMessage(), e);
        }
    }

    SessionKeySupplierImpl() {
    }

    @Override
    public KeyPair getKeyPair() {
        if (this.keyPair == null) {
            this.keyPair = GENERATOR.generateKeyPair();
        }
        return keyPair;
    }

    @Override
    public void refreshKeys() {
        this.keyPair = GENERATOR.generateKeyPair();
    }
}