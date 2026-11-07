package com.isolve.vapt.report;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** The outcome of executing one catalog finding (or one business rule / authorization
 *  check) against a project. This is the unit every report, retest and closure
 *  template is built from. */
public class FindingResult {

    public enum Status { PASS, FAIL, BLOCKED, SKIPPED, NOT_APPLICABLE }

    private String findingId;          // e.g. VAPT-046
    private String title;
    private String projectName;
    private String environment;
    private String module;
    private String severity;
    private String cweScore;
    private String endpointOrPage;
    private String role;
    private Status status;
    private String expected;
    private String actual;
    private String maskedRequest;
    private String maskedResponse;
    private List<String> evidencePaths = new ArrayList<>(); // screenshots / logs, already masked
    private Instant executedAt = Instant.now();
    private String executedBy; // "AI-Automation" | tester name for manual results
    private String notes;

    // Regression / lifecycle tracking
    private String firstRaisedDate;
    private String retestDate;
    private String closureStatus; // OPEN | FIXED-PENDING-RETEST | CLOSED | REOPENED

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getProjectName() { return projectName; }
    public void setProjectName(String projectName) { this.projectName = projectName; }
    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }
    public String getModule() { return module; }
    public void setModule(String module) { this.module = module; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getCweScore() { return cweScore; }
    public void setCweScore(String cweScore) { this.cweScore = cweScore; }
    public String getEndpointOrPage() { return endpointOrPage; }
    public void setEndpointOrPage(String endpointOrPage) { this.endpointOrPage = endpointOrPage; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getExpected() { return expected; }
    public void setExpected(String expected) { this.expected = expected; }
    public String getActual() { return actual; }
    public void setActual(String actual) { this.actual = actual; }
    public String getMaskedRequest() { return maskedRequest; }
    public void setMaskedRequest(String maskedRequest) { this.maskedRequest = maskedRequest; }
    public String getMaskedResponse() { return maskedResponse; }
    public void setMaskedResponse(String maskedResponse) { this.maskedResponse = maskedResponse; }
    public List<String> getEvidencePaths() { return evidencePaths; }
    public void setEvidencePaths(List<String> evidencePaths) { this.evidencePaths = evidencePaths; }
    public Instant getExecutedAt() { return executedAt; }
    public void setExecutedAt(Instant executedAt) { this.executedAt = executedAt; }
    public String getExecutedBy() { return executedBy; }
    public void setExecutedBy(String executedBy) { this.executedBy = executedBy; }
    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
    public String getFirstRaisedDate() { return firstRaisedDate; }
    public void setFirstRaisedDate(String firstRaisedDate) { this.firstRaisedDate = firstRaisedDate; }
    public String getRetestDate() { return retestDate; }
    public void setRetestDate(String retestDate) { this.retestDate = retestDate; }
    public String getClosureStatus() { return closureStatus; }
    public void setClosureStatus(String closureStatus) { this.closureStatus = closureStatus; }
}
