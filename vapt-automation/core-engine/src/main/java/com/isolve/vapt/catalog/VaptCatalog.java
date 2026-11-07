package com.isolve.vapt.catalog;

import java.util.List;

public class VaptCatalog {
    private String catalogName;
    private String source;
    private String version;
    private List<VaptFinding> findings;

    public String getCatalogName() { return catalogName; }
    public void setCatalogName(String catalogName) { this.catalogName = catalogName; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public List<VaptFinding> getFindings() { return findings; }
    public void setFindings(List<VaptFinding> findings) { this.findings = findings; }
}
