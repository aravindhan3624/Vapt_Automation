package com.isolve.vapt.config;

/**
 * Mandatory, explicit record of WHO authorized this testing and WHAT scope it covers.
 * The engine's bootstrap refuses to run (see ConfigLoader) if this block is missing,
 * so no execution can start against an environment without a traceable authorization
 * reference — this is what every report's "Scope & Authorization" section is built from.
 */
public class AuthorizationScope {
    private String authorizedBy;       // name/role of the person who approved this engagement
    private String approvalReference;  // ticket/email/engagement-letter reference
    private String approvalDate;       // ISO date
    private String allowedEnvironments; // e.g. "UAT only" — must never be "PROD"
    private String notes;

    public String getAuthorizedBy() { return authorizedBy; }
    public void setAuthorizedBy(String authorizedBy) { this.authorizedBy = authorizedBy; }
    public String getApprovalReference() { return approvalReference; }
    public void setApprovalReference(String approvalReference) { this.approvalReference = approvalReference; }
    public String getApprovalDate() { return approvalDate; }
    public void setApprovalDate(String approvalDate) { this.approvalDate = approvalDate; }
    public String getAllowedEnvironments() { return allowedEnvironments; }
    public void setAllowedEnvironments(String allowedEnvironments) { this.allowedEnvironments = allowedEnvironments; }
    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
}
