package com.isolve.vapt.config;

import java.util.List;
import java.util.Map;

/**
 * Generic, project-independent configuration model.
 * One YAML file per project (CKYC, CAO, CCM, ...) is deserialized into this POJO.
 * The core engine only ever programs against this class — never against a
 * project name — so onboarding a new application means writing a new YAML,
 * not new Java.
 */
public class ProjectConfig {

    private String projectName;
    private String environment;          // e.g. UAT, SIT, STAGING  (never PROD for active testing)
    private String baseUrl;               // UI base URL
    private String apiBaseUrl;            // API gateway base URL
    private String openApiSpecUrl;        // Swagger/OpenAPI, if available (null => manual endpoint inventory)

    private AuthConfig authentication;
    private List<RoleConfig> roles;
    private List<EndpointConfig> endpoints;
    private List<BusinessRuleConfig> businessRules;
    private DocumentMasterConfig documentMaster;
    private ZapConfig zap;
    private DbConfig database;            // optional, read-only validation
    private Map<String, String> testData; // keys referenced by step defs / business rules

    private AuthorizationScope scope;      // explicit written-authorization reference

    // --- getters / setters ---

    public String getProjectName() { return projectName; }
    public void setProjectName(String projectName) { this.projectName = projectName; }

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }

    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

    public String getApiBaseUrl() { return apiBaseUrl; }
    public void setApiBaseUrl(String apiBaseUrl) { this.apiBaseUrl = apiBaseUrl; }

    public String getOpenApiSpecUrl() { return openApiSpecUrl; }
    public void setOpenApiSpecUrl(String openApiSpecUrl) { this.openApiSpecUrl = openApiSpecUrl; }

    public AuthConfig getAuthentication() { return authentication; }
    public void setAuthentication(AuthConfig authentication) { this.authentication = authentication; }

    public List<RoleConfig> getRoles() { return roles; }
    public void setRoles(List<RoleConfig> roles) { this.roles = roles; }

    public List<EndpointConfig> getEndpoints() { return endpoints; }
    public void setEndpoints(List<EndpointConfig> endpoints) { this.endpoints = endpoints; }

    public List<BusinessRuleConfig> getBusinessRules() { return businessRules; }
    public void setBusinessRules(List<BusinessRuleConfig> businessRules) { this.businessRules = businessRules; }

    public DocumentMasterConfig getDocumentMaster() { return documentMaster; }
    public void setDocumentMaster(DocumentMasterConfig documentMaster) { this.documentMaster = documentMaster; }

    public ZapConfig getZap() { return zap; }
    public void setZap(ZapConfig zap) { this.zap = zap; }

    public DbConfig getDatabase() { return database; }
    public void setDatabase(DbConfig database) { this.database = database; }

    public Map<String, String> getTestData() { return testData; }
    public void setTestData(Map<String, String> testData) { this.testData = testData; }

    public AuthorizationScope getScope() { return scope; }
    public void setScope(AuthorizationScope scope) { this.scope = scope; }
}
