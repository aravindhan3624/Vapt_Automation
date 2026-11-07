package com.isolve.vapt.config;

import java.util.List;
import java.util.Map;

/** One API endpoint in the project's inventory (loaded from Swagger/OpenAPI, or configured
 *  manually when no spec exists). Drives API security regression + input-fuzzing. */
public class EndpointConfig {
    private String id;                 // stable key, e.g. "customer.getById"
    private String path;               // e.g. "/customer/{id}"
    private String method;             // GET | POST | PUT | PATCH | DELETE
    private String module;             // e.g. "DVS", "Customer", "Application"
    private boolean requiresAuth = true;
    private List<String> allowedRoles; // roles permitted to call this endpoint
    private List<ParameterConfig> pathParams;
    private List<ParameterConfig> queryParams;
    private List<ParameterConfig> bodyFields;
    private boolean containsSensitiveData = false; // PII/PAN/Aadhaar/account data in response
    private boolean fileUpload = false;
    private Map<String, Object> sampleRequestBody; // a known-good positive payload for mutation

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getModule() { return module; }
    public void setModule(String module) { this.module = module; }
    public boolean isRequiresAuth() { return requiresAuth; }
    public void setRequiresAuth(boolean requiresAuth) { this.requiresAuth = requiresAuth; }
    public List<String> getAllowedRoles() { return allowedRoles; }
    public void setAllowedRoles(List<String> allowedRoles) { this.allowedRoles = allowedRoles; }
    public List<ParameterConfig> getPathParams() { return pathParams; }
    public void setPathParams(List<ParameterConfig> pathParams) { this.pathParams = pathParams; }
    public List<ParameterConfig> getQueryParams() { return queryParams; }
    public void setQueryParams(List<ParameterConfig> queryParams) { this.queryParams = queryParams; }
    public List<ParameterConfig> getBodyFields() { return bodyFields; }
    public void setBodyFields(List<ParameterConfig> bodyFields) { this.bodyFields = bodyFields; }
    public boolean isContainsSensitiveData() { return containsSensitiveData; }
    public void setContainsSensitiveData(boolean containsSensitiveData) { this.containsSensitiveData = containsSensitiveData; }
    public boolean isFileUpload() { return fileUpload; }
    public void setFileUpload(boolean fileUpload) { this.fileUpload = fileUpload; }
    public Map<String, Object> getSampleRequestBody() { return sampleRequestBody; }
    public void setSampleRequestBody(Map<String, Object> sampleRequestBody) { this.sampleRequestBody = sampleRequestBody; }

    /** One field's metadata — drives which mutation/fuzz categories (Section 10 of the spec) apply. */
    public static class ParameterConfig {
        private String name;
        private String dataType;  // STRING | INTEGER | DECIMAL | BOOLEAN | DATE | ENUM | ARRAY | OBJECT | IDENTIFIER | FILE
        private boolean mandatory = true;
        private Integer maxLength;
        private String pattern;   // regex, if the API documents one

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDataType() { return dataType; }
        public void setDataType(String dataType) { this.dataType = dataType; }
        public boolean isMandatory() { return mandatory; }
        public void setMandatory(boolean mandatory) { this.mandatory = mandatory; }
        public Integer getMaxLength() { return maxLength; }
        public void setMaxLength(Integer maxLength) { this.maxLength = maxLength; }
        public String getPattern() { return pattern; }
        public void setPattern(String pattern) { this.pattern = pattern; }
    }
}
