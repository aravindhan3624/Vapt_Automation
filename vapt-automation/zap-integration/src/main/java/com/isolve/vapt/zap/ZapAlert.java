package com.isolve.vapt.zap;

/**
 * One ZAP alert, already redacted (MaskUtil) when read. ZAP alerts are leads to verify,
 * never confirmed findings on their own.
 */
public final class ZapAlert {
    public String pluginId = "";
    public String name = "";
    public String risk = "";          // Informational / Low / Medium / High
    public String confidence = "";
    public String url = "";
    public String param = "";
    public String evidence = "";
    public String cweId = "";
    public String wascId = "";
    public String solution = "";
    public String reference = "";

    @Override
    public String toString() {
        return risk + " | " + name + " | " + url;
    }
}
