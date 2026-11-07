package com.isolve.vapt.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.File;
import java.io.IOException;
import java.util.Locale;

/**
 * Loads a project's YAML configuration into {@link ProjectConfig} and enforces the
 * non-negotiable safety guardrails before any test is allowed to run:
 *   1. An authorization scope block must be present (who approved this, for which env)
 *      and must not still hold template placeholders such as "<<FILL ME>>".
 *   2. The target environment must not be / contain "PROD".
 *   3. Credentials are read only from the environment variables NAMED in the config —
 *      the YAML itself must never contain a literal password/token/API key.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static ProjectConfig load(File yamlFile) {
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            ProjectConfig config = mapper.readValue(yamlFile, ProjectConfig.class);
            validate(config);
            return config;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load project config: " + yamlFile, e);
        }
    }

    private static void validate(ProjectConfig config) {
        if (config.getScope() == null || isBlank(config.getScope().getAuthorizedBy())
                || isBlank(config.getScope().getApprovalReference())) {
            throw new SecurityException(
                "Refusing to proceed: project config for '" + config.getProjectName()
                + "' has no authorization scope (authorizedBy / approvalReference). "
                + "Fill in the 'scope:' block before running any security test.");
        }

        // Template text such as "<<FILL ME ...>>" is non-blank but is NOT an authorization.
        AuthorizationScope scope = config.getScope();
        if (isPlaceholder(scope.getAuthorizedBy()) || isPlaceholder(scope.getApprovalReference())
                || isPlaceholder(scope.getApprovalDate())) {
            throw new SecurityException(
                "Refusing to proceed: the 'scope:' block for '" + config.getProjectName()
                + "' still contains template placeholders (<<FILL ME>>). Record the real "
                + "approver, approval reference and date before running any security test.");
        }

        String env = config.getEnvironment() == null ? "" : config.getEnvironment().toUpperCase(Locale.ROOT);
        if (env.contains("PROD")) {
            throw new SecurityException(
                "Refusing to proceed: environment '" + config.getEnvironment()
                + "' looks like production. This framework only runs against UAT/SIT/STAGING "
                + "test environments with test accounts.");
        }

        if (config.getBaseUrl() == null && config.getApiBaseUrl() == null) {
            throw new IllegalStateException("Project config must set baseUrl and/or apiBaseUrl.");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static boolean isPlaceholder(String s) {
        return s != null && (s.contains("<<") || s.toUpperCase(Locale.ROOT).contains("FILL ME"));
    }
}
