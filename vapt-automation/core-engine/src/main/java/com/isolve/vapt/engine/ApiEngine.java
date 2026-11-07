package com.isolve.vapt.engine;

import com.isolve.vapt.config.ProjectConfig;
import com.isolve.vapt.config.ZapConfig;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.specification.RequestSpecification;

/**
 * Thin, reusable REST Assured wrapper. Every API call in the framework goes through
 * here so that routing traffic through OWASP ZAP (or not) is a single config switch,
 * never something copy-pasted into every test class.
 */
public final class ApiEngine {

    private final ProjectConfig project;
    private String bearerToken; // set by AuthEngine after login; never logged/printed

    public ApiEngine(ProjectConfig project) {
        this.project = project;
        configureZapProxyIfEnabled();
    }

    private void configureZapProxyIfEnabled() {
        ZapConfig zap = project.getZap();
        if (zap == null || !zap.isEnabled()) {
            return;
        }
        RestAssured.proxy(zap.getZapHost(), zap.getZapPort());
        RestAssured.useRelaxedHTTPSValidation();
    }

    public void setBearerToken(String token) {
        this.bearerToken = token;
    }

    /** Base request spec: base URI + (if present) a valid Bearer token. Tests that want
     *  to test WITHOUT the token, or with a tampered one, override explicitly — see
     *  Section 8 (Bearer token testing) of the architecture spec. */
    public RequestSpecification baseRequest() {
        RequestSpecification spec = RestAssured.given()
                .baseUri(project.getApiBaseUrl())
                .config(RestAssuredConfig.config().httpClient(
                        HttpClientConfig.httpClientConfig().setParam("http.connection.timeout", 15000)));
        if (bearerToken != null && !bearerToken.isBlank()) {
            spec = spec.header("Authorization", "Bearer " + bearerToken);
        }
        return spec;
    }

    /** Explicit no-auth request, for "missing token" / "unauthenticated access" checks. */
    public RequestSpecification unauthenticatedRequest() {
        return RestAssured.given().baseUri(project.getApiBaseUrl());
    }

    /** Request with a deliberately tampered/invalid/expired token, for negative auth tests. */
    public RequestSpecification requestWithToken(String overrideToken) {
        return RestAssured.given().baseUri(project.getApiBaseUrl())
                .header("Authorization", "Bearer " + overrideToken);
    }
}
