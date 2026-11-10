package com.isolve.vapt.passive;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Classifies a single value as personal / sensitive data. Pure functions; values are inspected,
 * never returned or stored. Whole-value matching plus field-name hints keeps false positives low
 * (a 10-digit id is not called a mobile number unless the field is named like one).
 */
public final class SensitiveData {

    public enum Type { PAN, AADHAAR, CARD, MOBILE, EMAIL, SECRET }

    private static final Pattern PAN_STRICT = Pattern.compile("^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$");
    private static final Pattern PAN_LOOSE = Pattern.compile("^[A-Z]{5}[0-9]{4}[A-Z]$");
    private static final Pattern TWELVE = Pattern.compile("^[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}$");
    private static final Pattern CARD = Pattern.compile("^[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,7}$");
    private static final Pattern MOBILE = Pattern.compile("^(?:\\+?91[ -]?|0)?[6-9][0-9]{9}$");
    private static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern MASKED = Pattern.compile(".*(?:[Xx*#•]{4,}|[Xx*]{2,}[ -]?[Xx*]{2,}).*");

    // "pan", "panNo", "pan_number", "customerPan", "kyc_pan_no" - but not "company", "japan".
    private static final Pattern K_PAN = Pattern.compile(
            "(?:(?i)(?:^|.*[-_.])pan(?:_?(?:no|num|number|card|id))?(?:[-_.].*)?$)|(?:.*[a-z]Pan(?:[A-Z_].*)?$)|(?:(?i)^pan(?:no|num|number|card|id)$)");
    private static final Pattern K_AADHAAR = Pattern.compile("(?i).*(?:aadhaar|aadhar|adhar|uidai|uid_?no).*");
    private static final Pattern K_CARD = Pattern.compile("(?i).*(?:card_?no|card_?num|cardnumber|ccnum|debit|credit|pan_?card_?no).*");
    private static final Pattern K_MOBILE = Pattern.compile("(?i).*(?:mobile|mob_?no|phone|contact_?no|cell).*");
    private static final Pattern K_EMAIL = Pattern.compile("(?i).*(?:e_?mail|mail_?id).*");
    private static final Pattern K_SECRET = Pattern.compile(
            "(?:(?i)^(?:.*[_-])?(?:password|passwd|pwd|pass_?word|pin|mpin|tpin|otp|cvv|cvv2|secret|client_?secret|private_?key|secret_?key)$)"
            + "|(?:^.*[a-z](?:Password|Passwd|Pwd|Pin|Mpin|Tpin|Otp|Cvv|Secret|SecretKey|PrivateKey)$)");

    private SensitiveData() {
    }

    /** Result of classifying one value: its type (or null) and whether it is masked. */
    public record Hit(Type type, boolean masked) {
    }

    /**
     * @param key   field name (last JSON key), may be null
     * @param value the value as text
     * @return a hit, or null when the value is not sensitive
     */
    public static Hit classify(String key, String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.isEmpty() || v.length() > 200) return null;
        String k = key == null ? "" : key;

        if (K_SECRET.matcher(k).matches() && !v.equalsIgnoreCase("null") && !v.equalsIgnoreCase("true")
                && !v.equalsIgnoreCase("false")) {
            return new Hit(Type.SECRET, isMasked(v));
        }
        boolean masked = isMasked(v);
        if (masked) {
            if (K_AADHAAR.matcher(k).matches()) return new Hit(Type.AADHAAR, true);
            if (K_CARD.matcher(k).matches()) return new Hit(Type.CARD, true);
            if (K_PAN.matcher(k).matches()) return new Hit(Type.PAN, true);
            if (K_MOBILE.matcher(k).matches()) return new Hit(Type.MOBILE, true);
            if (K_EMAIL.matcher(k).matches()) return new Hit(Type.EMAIL, true);
            return null;
        }
        String up = v.toUpperCase(Locale.ROOT);
        if (PAN_STRICT.matcher(up).matches() || (K_PAN.matcher(k).matches() && PAN_LOOSE.matcher(up).matches())) {
            return new Hit(Type.PAN, false);
        }
        if (TWELVE.matcher(v).matches()) {
            String d = v.replaceAll("[ -]", "");
            if (K_AADHAAR.matcher(k).matches() || (d.charAt(0) >= '2' && verhoeffValid(d) && !K_CARD.matcher(k).matches())) {
                return new Hit(Type.AADHAAR, false);
            }
        }
        if (CARD.matcher(v).matches()) {
            String d = v.replaceAll("[ -]", "");
            if (d.length() >= 13 && d.length() <= 19 && luhnValid(d)
                    && (K_CARD.matcher(k).matches() || (d.length() == 16 && (d.charAt(0) == '4' || d.charAt(0) == '5')))) {
                return new Hit(Type.CARD, false);
            }
        }
        if (MOBILE.matcher(v).matches() && (K_MOBILE.matcher(k).matches() || v.startsWith("+91"))) {
            return new Hit(Type.MOBILE, false);
        }
        if (EMAIL.matcher(v).matches()) return new Hit(Type.EMAIL, false);
        return null;
    }

    public static boolean isMasked(String v) {
        return MASKED.matcher(v).matches();
    }

    static boolean luhnValid(String digits) {
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (dbl) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static final int[][] D = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
            {3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
            {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
            {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}};
    private static final int[][] P = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
            {8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
            {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}};

    /** Verhoeff checksum (used by Aadhaar numbers). */
    static boolean verhoeffValid(String digits) {
        int c = 0;
        for (int i = 0; i < digits.length(); i++) {
            int n = digits.charAt(digits.length() - 1 - i) - '0';
            c = D[c][P[i % 8][n]];
        }
        return c == 0;
    }
}
