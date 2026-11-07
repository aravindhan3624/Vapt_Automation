package com.isolve.vapt.config;

/** Optional, strictly read-only DB validation connection. Credentials come from env vars only.
 *  The engine never issues write/DDL/DML statements through this config. */
public class DbConfig {
    private boolean enabled = false;
    private String jdbcUrl;
    private String usernameEnvVar;
    private String passwordEnvVar;
    private boolean readOnly = true; // engine refuses to run if this is ever set false

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getJdbcUrl() { return jdbcUrl; }
    public void setJdbcUrl(String jdbcUrl) { this.jdbcUrl = jdbcUrl; }
    public String getUsernameEnvVar() { return usernameEnvVar; }
    public void setUsernameEnvVar(String usernameEnvVar) { this.usernameEnvVar = usernameEnvVar; }
    public String getPasswordEnvVar() { return passwordEnvVar; }
    public void setPasswordEnvVar(String passwordEnvVar) { this.passwordEnvVar = passwordEnvVar; }
    public boolean isReadOnly() { return readOnly; }
    public void setReadOnly(boolean readOnly) { this.readOnly = readOnly; }
}
