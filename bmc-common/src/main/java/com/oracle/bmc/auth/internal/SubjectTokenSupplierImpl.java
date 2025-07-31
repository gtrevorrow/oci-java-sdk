package com.oracle.bmc.auth.internal;

import java.util.function.Supplier;

public class SubjectTokenSupplierImpl implements Supplier<String> {

    String subjectToken ;

    public SubjectTokenSupplierImpl(String subjectToken) {
        this.subjectToken = subjectToken;
    }

    @Override
    public String get() {
        // This method should return the subject token.
        // The actual implementation would depend on how the subject token is obtained.
        // For example, it could be from a JWT, OAuth2 token, etc.
        return subjectToken; // Placeholder for actual token retrieval logic
    }
}
