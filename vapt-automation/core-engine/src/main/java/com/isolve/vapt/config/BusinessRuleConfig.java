package com.isolve.vapt.config;

/** A project-specific business/security rule (Section 11/19 of the spec) — e.g.
 *  "Maker cannot approve their own transaction". The core engine evaluates these
 *  generically; it never contains the rule text itself. */
public class BusinessRuleConfig {
    private String ruleId;
    private String module;
    private String condition;          // human-readable precondition
    private String expectedResult;     // human-readable expected secure behaviour
    private String severity;           // Critical | High | Medium | Low
    private String verificationMethod; // UI | API | DB | MIXED

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getModule() { return module; }
    public void setModule(String module) { this.module = module; }
    public String getCondition() { return condition; }
    public void setCondition(String condition) { this.condition = condition; }
    public String getExpectedResult() { return expectedResult; }
    public void setExpectedResult(String expectedResult) { this.expectedResult = expectedResult; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getVerificationMethod() { return verificationMethod; }
    public void setVerificationMethod(String verificationMethod) { this.verificationMethod = verificationMethod; }
}
