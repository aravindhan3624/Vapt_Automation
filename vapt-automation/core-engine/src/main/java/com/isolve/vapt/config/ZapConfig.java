package com.isolve.vapt.config;

/** OWASP ZAP proxy connection settings — kept configurable per environment/machine,
 *  never hardcoded to localhost:8080 inside the engine. */
public class ZapConfig {
    private boolean enabled = false;
    private String zapHost = "localhost";
    private int zapPort = 8080;
    private String apiKeyEnvVar;     // name of env var holding the ZAP API key
    private String scanPolicyName;   // e.g. "Banking-Safe-Active-Scan"
    private String contextName;
    private int spiderTimeoutSeconds = 300;
    private int activeScanTimeoutSeconds = 1800;
    private String reportOutputDir = "../../reports/output";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getZapHost() { return zapHost; }
    public void setZapHost(String zapHost) { this.zapHost = zapHost; }
    public int getZapPort() { return zapPort; }
    public void setZapPort(int zapPort) { this.zapPort = zapPort; }
    public String getApiKeyEnvVar() { return apiKeyEnvVar; }
    public void setApiKeyEnvVar(String apiKeyEnvVar) { this.apiKeyEnvVar = apiKeyEnvVar; }
    public String getScanPolicyName() { return scanPolicyName; }
    public void setScanPolicyName(String scanPolicyName) { this.scanPolicyName = scanPolicyName; }
    public String getContextName() { return contextName; }
    public void setContextName(String contextName) { this.contextName = contextName; }
    public int getSpiderTimeoutSeconds() { return spiderTimeoutSeconds; }
    public void setSpiderTimeoutSeconds(int spiderTimeoutSeconds) { this.spiderTimeoutSeconds = spiderTimeoutSeconds; }
    public int getActiveScanTimeoutSeconds() { return activeScanTimeoutSeconds; }
    public void setActiveScanTimeoutSeconds(int activeScanTimeoutSeconds) { this.activeScanTimeoutSeconds = activeScanTimeoutSeconds; }
    public String getReportOutputDir() { return reportOutputDir; }
    public void setReportOutputDir(String reportOutputDir) { this.reportOutputDir = reportOutputDir; }
}
