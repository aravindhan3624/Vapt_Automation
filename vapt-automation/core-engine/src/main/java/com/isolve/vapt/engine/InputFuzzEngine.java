package com.isolve.vapt.engine;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Safe, non-destructive payload catalogs for input-validation regression (Section 10),
 * SQL-injection detection (Section 11 / catalog VAPT-046) and reflected/stored XSS
 * detection (Section 12 / catalog VAPT-022, VAPT-045).
 *
 * Rules enforced by design:
 *   - No payload here attempts to modify, delete or exfiltrate data (no stacked queries,
 *     no DROP/UPDATE/INSERT, no UNION-based data extraction attempts).
 *   - SQLi detection is evidence-based: a verdict requires an observable error-based or
 *     boolean-based signal (DB error string, stack trace, or a true/false response-size
 *     delta between the two boolean payloads) — never "it returned HTTP 500" alone.
 *   - Intended for authorized UAT/test environments only; see ConfigLoader guardrails.
 */
public final class InputFuzzEngine {

    /** Generic boundary/type/structural mutations (Section 10) — applies by declared dataType. */
    public static Map<String, List<Object>> genericMutations(String dataType) {
        return switch (dataType == null ? "STRING" : dataType.toUpperCase()) {
            case "INTEGER", "DECIMAL" -> Map.of(
                    "null", Collections.singletonList(null), // List.of rejects null elements
                    "boundary", List.of(0, -1, Integer.MAX_VALUE, Long.MAX_VALUE),
                    "wrongType", List.of("abc", "1e309", "NaN"));
            case "STRING" -> Map.of(
                    "null", Collections.singletonList(null),
                    "blank", List.of("", "   "),
                    "boundary", List.of("A".repeat(1), "A".repeat(255), "A".repeat(10000)),
                    "specialChars", List.of("' OR 1=1", "<script>", "\u0000", "日本語", "	\n\r"));
            case "DATE" -> Map.of(
                    "invalid", List.of("31-13-2026", "0000-00-00", "not-a-date"));
            case "BOOLEAN" -> Map.of(
                    "invalid", List.of("maybe", "1", "0", "TRUE_X"));
            case "IDENTIFIER" -> Map.of(
                    "foreignObject", List.of("OTHER_USER_OBJECT_ID"), // resolved by caller to a real test object
                    "sequential", List.of("1", "0", "-1"));
            default -> Map.of();
        };
    }

    /** VAPT-046: SQL injection detection payloads — error-based and boolean-based only. */
    public static List<String> sqlInjectionProbes() {
        return List.of(
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='2",
                "1 AND 1=1",
                "1 AND 1=2",
                "' --",
                "' ; --"
        );
    }

    /** Known DB-error / stack-trace signatures that, if present in a response the
     *  application should have sanitized, are evidence of SQLi (not proof of exploit). */
    public static List<String> sqlErrorSignatures() {
        return List.of(
                "SQLException", "ODBC", "syntax error", "unclosed quotation mark",
                "SQLSTATE", "ORA-0", "SQL syntax", "PostgreSQL", "SQLite3::", "System.Data.SqlClient"
        );
    }

    /** VAPT-022 / VAPT-045: non-executing detection payloads — safe to submit to a UAT form. */
    public static List<String> xssProbes() {
        return List.of(
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "\"><script>alert(1)</script>"
        );
    }

    /** VAPT-038/036/037: path-traversal / LFI / RFI detection payloads (read-only probes). */
    public static List<String> pathTraversalProbes() {
        return List.of(
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "..%2f..%2f..%2fetc%2fpasswd",
                "http://169.254.169.254/latest/meta-data/" // SSRF/metadata probe, VAPT-058
        );
    }
}
