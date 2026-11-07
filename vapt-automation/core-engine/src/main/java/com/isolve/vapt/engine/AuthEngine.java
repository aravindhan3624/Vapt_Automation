package com.isolve.vapt.engine;

import com.isolve.vapt.config.AuthConfig;
import com.isolve.vapt.config.ProjectConfig;
import com.isolve.vapt.config.RoleConfig;
import io.restassured.response.Response;

import java.util.Optional;

/**
 * Resolves test credentials strictly from environment variables (never from YAML, never
 * from Java literals) and performs API_LOGIN to obtain a bearer token per role.
 *
 * To run anything, export the env vars named in the project's roles[].usernameEnvVar /
 * passwordEnvVar before launching Maven/TestNG, e.g.:
 *   CKYC_MAKER_USER / CKYC_MAKER_PASS, CKYC_CHECKER_USER / CKYC_CHECKER_PASS, ...
 */
public final class AuthEngine {

    private final ProjectConfig project;
    private final ApiEngine apiEngine;

    public AuthEngine(ProjectConfig project, ApiEngine apiEngine) {
        this.project = project;
        this.apiEngine = apiEngine;
    }

    public String loginAs(String roleName) {
        RoleConfig role = project.getRoles().stream()
                .filter(r -> r.getRoleName().equalsIgnoreCase(roleName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown role: " + roleName));

        String username = requireEnv(role.getUsernameEnvVar());
        String password = requireEnv(role.getPasswordEnvVar());

        AuthConfig auth = project.getAuthentication();
        if (!"API_LOGIN".equalsIgnoreCase(auth.getType())) {
            throw new UnsupportedOperationException(
                "AuthEngine.loginAs() currently wires API_LOGIN; FORM_LOGIN is driven via the UI engine instead.");
        }

        Response resp = apiEngine.unauthenticatedRequest()
                .contentType("application/json")
                .body(java.util.Map.of(
                        auth.getUsernameField(), username,
                        auth.getPasswordField(), password))
                .post(auth.getLoginUrl());

        if (resp.getStatusCode() != 200) {
            throw new IllegalStateException(
                "Login as role '" + roleName + "' failed with status " + resp.getStatusCode()
                + " — verify test account is valid in this UAT environment.");
        }

        String token = resp.jsonPath().getString(jsonPathWithoutDollar(auth.getTokenJsonPath()));
        apiEngine.setBearerToken(token);
        return token;
    }

    private String jsonPathWithoutDollar(String path) {
        // RestAssured JsonPath doesn't want a leading "$."
        return path.startsWith("$.") ? path.substring(2) : path;
    }

    private String requireEnv(String envVarName) {
        String value = Optional.ofNullable(System.getenv(envVarName)).orElse("");
        if (value.isBlank()) {
            throw new IllegalStateException(
                "Required test-account environment variable '" + envVarName + "' is not set. "
                + "Set it to a UAT test account before running security tests.");
        }
        return value;
    }
}
