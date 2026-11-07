package com.isolve.vapt.recorder;

import java.util.ArrayList;
import java.util.List;

/**
 * One captured API call, written to the capture file only after redaction.
 * Header VALUES are never kept (names only); bodies are redacted by {@link JsonRedactor}.
 */
public final class CaptureRecord {
    public String capturedAt = "";
    public String project = "";
    public String role = "";
    public String module = "";            // label typed in the overlay, may be empty
    public String method = "";
    public String scheme = "";
    public String host = "";
    public String path = "";
    public List<String> queryParamNames = new ArrayList<>();
    public List<String> requestHeaderNames = new ArrayList<>();
    public String requestContentType = "";
    public String requestBody;             // redacted; plain text when decrypted
    public boolean requestDecrypted;       // true when the plain body came from the in-page hook
    public int status;
    public String responseContentType = "";
    public String responseBody;            // redacted; plain text when decrypted
    public boolean responseDecrypted;
}
