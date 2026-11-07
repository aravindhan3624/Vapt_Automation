package com.isolve.vapt.config;

import java.util.List;

/** Project-specific Document/Image Master (Section 13) — POI/POA codes are never
 *  universal across banking projects, so they live entirely in project YAML. */
public class DocumentMasterConfig {
    private List<DocumentType> documentTypes;

    public List<DocumentType> getDocumentTypes() { return documentTypes; }
    public void setDocumentTypes(List<DocumentType> documentTypes) { this.documentTypes = documentTypes; }

    public static class DocumentType {
        private String documentName;
        private String poiCode;
        private String poaCode;
        private boolean poia; // POI+POA combined document
        private List<String> allowedExtensions;
        private Integer maxSizeMb;

        public String getDocumentName() { return documentName; }
        public void setDocumentName(String documentName) { this.documentName = documentName; }
        public String getPoiCode() { return poiCode; }
        public void setPoiCode(String poiCode) { this.poiCode = poiCode; }
        public String getPoaCode() { return poaCode; }
        public void setPoaCode(String poaCode) { this.poaCode = poaCode; }
        public boolean isPoia() { return poia; }
        public void setPoia(boolean poia) { this.poia = poia; }
        public List<String> getAllowedExtensions() { return allowedExtensions; }
        public void setAllowedExtensions(List<String> allowedExtensions) { this.allowedExtensions = allowedExtensions; }
        public Integer getMaxSizeMb() { return maxSizeMb; }
        public void setMaxSizeMb(Integer maxSizeMb) { this.maxSizeMb = maxSizeMb; }
    }
}
