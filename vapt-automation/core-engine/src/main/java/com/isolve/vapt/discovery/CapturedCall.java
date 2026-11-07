package com.isolve.vapt.discovery;

import java.util.List;

/**
 * One HTTP call read from a passive capture (Burp "Save items" XML or a HAR export).
 *
 * PASSIVE DISCOVERY ONLY. This object carries nothing secret: header and parameter
 * NAMES are kept, their VALUES are deliberately dropped at parse time. No cookie,
 * token, password, OTP or body value is ever stored here.
 */
public final class CapturedCall {
    public String method = "GET";
    public String scheme = "";
    public String host = "";
    public String path = "";                 // path only, no query string
    public List<String> queryParamNames = List.of();
    public List<String> requestBodyParamNames = List.of();   // best-effort; names only
    public List<String> requestHeaderNames = List.of();      // names only
    public String requestContentType = "";
    public int status = 0;
    public String responseContentType = "";

    public String methodAndPath() {
        return method + " " + path;
    }
}
