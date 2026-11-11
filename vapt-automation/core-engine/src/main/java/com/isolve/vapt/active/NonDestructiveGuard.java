package com.isolve.vapt.active;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Decides whether a recorded endpoint may be re-sent by an active check. It fails CLOSED: only
 * endpoints that clearly read data are allowed; anything that creates, changes, approves, deletes,
 * submits or otherwise alters state, and anything it cannot classify, is refused.
 *
 * This is the guard that keeps Phase 6 non-destructive even though the checks re-send real
 * requests. It is deliberately conservative: a safe endpoint wrongly refused only means one fewer
 * check; a dangerous endpoint wrongly allowed could change bank data, so the default is refuse.
 */
public final class NonDestructiveGuard {

    public enum Decision { SAFE_READ, REFUSED_STATE_CHANGING, REFUSED_UNKNOWN }

    /** Path contains any of these -> state-changing, never re-sent. */
    private static final Pattern STATE_CHANGING = Pattern.compile("(?i)(?:^|[/_-])(?:"
            + "create|add|new|insert|save|store|update|edit|modify|change|patch|put|set|"
            + "delete|remove|drop|del|purge|clear|truncate|"
            + "approve|reject|verify|authorize|authorise|confirm|submit|send|post|push|sync|"
            + "lock|unlock|enable|disable|activate|deactivate|block|unblock|suspend|"
            + "revoke|reset|regenerate|rotate|generate|issue|"
            + "upload|import|export|download|print|"
            + "assign|allocate|transfer|move|merge|split|"
            + "crud|bulk|batch|process|execute|run|trigger|invoke|perform|do[A-Z]|"
            + "login|logout|signin|signout|register|signup|otp|pay|order|checkout"
            + ")(?:[/_-]|[A-Z]|$)");

    /** Path contains one of these read verbs -> eligible (still must not match STATE_CHANGING). */
    private static final Pattern READ_LIKE = Pattern.compile("(?i)(?:^|[/_-])(?:"
            + "get|view|list|fetch|read|show|find|search|query|lookup|browse|"
            + "details?|detail|info|data|master|masters|config|configuration|setting|settings|"
            + "status|state|report|reports|dashboard|summary|count|stats|statistics|"
            + "permission|permissions|role|roles|menu|page|pending|history|audit|log|logs|"
            + "image|images|photo|document|documents|doc|file|preview|thumbnail|thumb"
            + ")(?:[/_-]|[A-Z]|s?$)");

    private NonDestructiveGuard() {
    }

    /**
     * @param method HTTP method as recorded (GET/POST/...)
     * @param path   URL path (query string excluded)
     */
    public static Decision classify(String method, String path) {
        String m = method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
        String p = path == null ? "" : path;

        // Methods that change state by definition are never eligible, whatever the path says.
        if (m.equals("DELETE") || m.equals("PUT") || m.equals("PATCH")) return Decision.REFUSED_STATE_CHANGING;

        if (STATE_CHANGING.matcher(p).find()) return Decision.REFUSED_STATE_CHANGING;

        // GET of an image/document or a clearly read path is safe.
        if (m.equals("GET")) {
            if (READ_LIKE.matcher(p).find() || isStaticAsset(p)) return Decision.SAFE_READ;
            // A plain GET with no verb and no id-looking segment (e.g. a listing root) is still a read.
            if (!p.matches(".*/\\d{3,}.*")) return Decision.SAFE_READ;
            return Decision.REFUSED_UNKNOWN;
        }
        // POST is used for reads in this API (e.g. getCustomerDetailsV2); allow only when the path
        // clearly reads and does not match any state-changing verb above.
        if (m.equals("POST") && READ_LIKE.matcher(p).find()) return Decision.SAFE_READ;

        return Decision.REFUSED_UNKNOWN;
    }

    public static boolean isSafeRead(String method, String path) {
        return classify(method, path) == Decision.SAFE_READ;
    }

    private static boolean isStaticAsset(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        for (String ext : List.of(".jpg", ".jpeg", ".png", ".gif", ".pdf", ".bmp", ".tiff", ".webp",
                ".js", ".css", ".svg", ".ico", ".woff", ".woff2")) {
            if (p.endsWith(ext)) return true;
        }
        return p.contains("/ckyc_image/") || p.contains("/image/") || p.contains("/assets/");
    }
}
