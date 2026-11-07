package com.isolve.vapt.catalog;

import java.util.List;

/** One row of the banking-domain VAPT checklist (master catalog), generated from
 *  VAPT_Banking Domain check list_Final (1).xlsx. Project test suites reference
 *  findings by id; the catalog itself never changes per project. */
public class VaptFinding {
    private String id;                 // e.g. VAPT-046
    private String title;
    private String subOf;              // parent finding id/title, for grouped sub-checks
    private String riskDescription;
    private Object cweScore;
    private String severity;           // Critical | High | Medium | Low
    private String remediation;
    private String testedBy;           // "AI" | "Manual" | "AI + Manual"
    private boolean automatable;
    private String reason;
    private List<String> testSteps;
    private List<String> expectedSecureResult;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getSubOf() { return subOf; }
    public void setSubOf(String subOf) { this.subOf = subOf; }
    public String getRiskDescription() { return riskDescription; }
    public void setRiskDescription(String riskDescription) { this.riskDescription = riskDescription; }
    public Object getCweScore() { return cweScore; }
    public void setCweScore(Object cweScore) { this.cweScore = cweScore; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }
    public String getTestedBy() { return testedBy; }
    public void setTestedBy(String testedBy) { this.testedBy = testedBy; }
    public boolean isAutomatable() { return automatable; }
    public void setAutomatable(boolean automatable) { this.automatable = automatable; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public List<String> getTestSteps() { return testSteps; }
    public void setTestSteps(List<String> testSteps) { this.testSteps = testSteps; }
    public List<String> getExpectedSecureResult() { return expectedSecureResult; }
    public void setExpectedSecureResult(List<String> expectedSecureResult) { this.expectedSecureResult = expectedSecureResult; }
}
