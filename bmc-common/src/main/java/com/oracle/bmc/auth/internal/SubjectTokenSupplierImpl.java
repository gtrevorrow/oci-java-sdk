package com.oracle.bmc.auth.internal;

import java.util.function.Supplier;

public class SubjectTokenSupplierImpl implements Supplier<String> {

    private final String subjectToken;

    public SubjectTokenSupplierImpl(String subjectToken) {
        if (subjectToken == null || subjectToken.isEmpty()) {
            throw new IllegalArgumentException("Subject token must not be null or empty");
        }
        this.subjectToken = subjectToken;
    }

    @Override
    public String get() {
        return subjectToken;
    }
}