/**
 * Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth.internal;

import java.util.concurrent.CompletableFuture;

public interface AsyncFederationClient {

    /**
     * Gets a security token from the federation endpoint. May use a cached token if
     * it judged to
     * still be valid.
     *
     * @return A CompletableFuture that will complete with a security token that can
     *         be used to authenticate requests.
     */
    CompletableFuture<String> getSecurityToken();

    /**
     * Gets a security token from the federation endpoint. This will always retrieve
     * a new token
     * from the federation endpoint and does not use a cached token.
     *
     * @return A CompletableFuture that will complete with a security token that can
     *         be used to authenticate requests.
     */
    CompletableFuture<String> refreshAndGetSecurityToken();

    /**
     * Get a claim embedded in the security token. May use the cached token if it is
     * judged to still
     * be valid.
     */
    String getStringClaim(String key);
}