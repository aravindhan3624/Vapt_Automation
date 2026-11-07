package com.isolve.vapt.config;

import java.util.Map;

/** One application role (Maker/Checker/Admin/Viewer...) and which test account env-vars
 *  the engine should use to authenticate as that role. */
public class RoleConfig {
    private String roleName;
    private String usernameEnvVar;
    private String passwordEnvVar;
    private Map<String, String> permissions; // action -> ALLOWED | FORBIDDEN, drives authorization matrix

    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }
    public String getUsernameEnvVar() { return usernameEnvVar; }
    public void setUsernameEnvVar(String usernameEnvVar) { this.usernameEnvVar = usernameEnvVar; }
    public String getPasswordEnvVar() { return passwordEnvVar; }
    public void setPasswordEnvVar(String passwordEnvVar) { this.passwordEnvVar = passwordEnvVar; }
    public Map<String, String> getPermissions() { return permissions; }
    public void setPermissions(Map<String, String> permissions) { this.permissions = permissions; }
}
