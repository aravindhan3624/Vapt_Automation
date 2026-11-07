package com.isolve.vapt.util;

import java.util.regex.Pattern;

/**
 * Masks secrets/PII before anything is written to a report, log or evidence file.
 * Applied to every captured request/response (Section 21/8 of the architecture spec) —
 * no Authorization header, OTP, password, session id or card/PAN/Aadhaar value is ever
 * persisted in the clear.
 */
public final class MaskUtil {

    private static final Pattern BEARER = Pattern.compile("(?i)(Bearer\\s+)[A-Za-z0-9\\-_.]+");
    private static final Pattern AUTH_HEADER_VALUE = Pattern.compile("(?i)(\"Authorization\"\\s*:\\s*\")[^\"]+(\")");
    private static final Pattern PASSWORD_FIELD = Pattern.compile("(?i)(\"password\"\\s*:\\s*\")[^\"]+(\")");
    private static final Pattern OTP_FIELD = Pattern.compile("(?i)(\"otp\"\\s*:\\s*\")[^\"]+(\")");
    private static final Pattern PAN = Pattern.compile("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b");            // Indian PAN
    private static final Pattern AADHAAR = Pattern.compile("\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b");    // Aadhaar-shaped
    private static final Pattern CARD = Pattern.compile("\\b(?:\\d[ -]*?){13,19}\\b");

    private MaskUtil() {}

    public static String mask(String raw) {
        if (raw == null) return null;
        String out = raw;
        out = BEARER.matcher(out).replaceAll("$1***MASKED***");
        out = AUTH_HEADER_VALUE.matcher(out).replaceAll("$1***MASKED***$2");
        out = PASSWORD_FIELD.matcher(out).replaceAll("$1***MASKED***$2");
        out = OTP_FIELD.matcher(out).replaceAll("$1***MASKED***$2");
        out = PAN.matcher(out).replaceAll("**MASKED-PAN**");
        out = AADHAAR.matcher(out).replaceAll("**MASKED-AADHAAR**");
        out = CARD.matcher(out).replaceAll("**MASKED-CARD**");
        return out;
    }
}
