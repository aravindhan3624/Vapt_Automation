package com.isolve.vapt.config;

/** How the engine logs in / obtains a token for a given project. Credentials are NEVER
 *  hardcoded here — only env-variable / secret-manager REFERENCES are stored in YAML. */
public class AuthConfig {
    private String type;             // FORM_LOGIN | API_LOGIN | OAUTH2 | BEARER_STATIC
    private String loginUrl;         // UI login page or API login endpoint
    private String usernameField;
    private String passwordField;
    private String otpRequired;      // "true"/"false" as string, or "conditional"
    private String tokenJsonPath;    // e.g. "$.data.accessToken" for API_LOGIN responses
    private String usernameEnvVar;   // name of env var holding the test username
    private String passwordEnvVar;   // name of env var holding the test password

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getLoginUrl() { return loginUrl; }
    public void setLoginUrl(String loginUrl) { this.loginUrl = loginUrl; }
    public String getUsernameField() { return usernameField; }
    public void setUsernameField(String usernameField) { this.usernameField = usernameField; }
    public String getPasswordField() { return passwordField; }
    public void setPasswordField(String passwordField) { this.passwordField = passwordField; }
    public String getOtpRequired() { return otpRequired; }
    public void setOtpRequired(String otpRequired) { this.otpRequired = otpRequired; }
    public String getTokenJsonPath() { return tokenJsonPath; }
    public void setTokenJsonPath(String tokenJsonPath) { this.tokenJsonPath = tokenJsonPath; }
    public String getUsernameEnvVar() { return usernameEnvVar; }
    public void setUsernameEnvVar(String usernameEnvVar) { this.usernameEnvVar = usernameEnvVar; }
    public String getPasswordEnvVar() { return passwordEnvVar; }
    public void setPasswordEnvVar(String passwordEnvVar) { this.passwordEnvVar = passwordEnvVar; }
}
