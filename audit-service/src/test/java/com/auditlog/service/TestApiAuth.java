package com.auditlog.service;

import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Shared API key used by the test profile's bootstrap client. */
final class TestApiAuth {

    static final String KEY = "test-admin-key-not-for-production";

    private TestApiAuth() {}

    static MockHttpServletRequestBuilder withKey(MockHttpServletRequestBuilder request) {
        return request.header("X-API-Key", KEY);
    }
}
