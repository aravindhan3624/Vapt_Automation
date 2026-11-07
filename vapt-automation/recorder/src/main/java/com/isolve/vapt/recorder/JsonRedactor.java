package com.isolve.vapt.recorder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.isolve.vapt.util.MaskUtil;

import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Redacts captured bodies before they are kept anywhere: values under sensitive keys are
 * replaced, and every remaining string goes through MaskUtil (bearer tokens, PAN, Aadhaar,
 * card numbers...). Non-JSON text is masked with MaskUtil only.
 */
public final class JsonRedactor {

    public static final String REDACTED = "***REDACTED***";

    private static final ObjectMapper M = new ObjectMapper();
    private static final Pattern SENSITIVE_KEY = Pattern.compile(
            "(?i).*(pass(word|wd)?|pwd|otp|pin|cvv|token|secret|csrf|xsrf|session|cookie|authori[sz]ation|"
                    + "api[_-]?key|private|credential|signature).*");

    private JsonRedactor() {}

    public static boolean isSensitiveKey(String key) {
        return key != null && SENSITIVE_KEY.matcher(key).matches();
    }

    public static String redact(String body, int maxChars) {
        if (body == null || body.isEmpty()) return body;
        String out;
        try {
            JsonNode n = M.readTree(body);
            out = (n == null || n.isMissingNode()) ? MaskUtil.mask(body) : M.writeValueAsString(walk(n));
        } catch (Exception notJson) {
            out = MaskUtil.mask(body);
        }
        return out.length() > maxChars ? out.substring(0, maxChars) + "...[truncated " + out.length() + " chars]" : out;
    }

    private static JsonNode walk(JsonNode n) {
        if (n.isObject()) {
            ObjectNode o = (ObjectNode) n;
            Iterator<Map.Entry<String, JsonNode>> it = o.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                if (isSensitiveKey(e.getKey()) && !e.getValue().isNull() && !e.getValue().isContainerNode()) {
                    e.setValue(TextNode.valueOf(REDACTED));
                } else {
                    e.setValue(walk(e.getValue()));
                }
            }
            return o;
        }
        if (n.isArray()) {
            ArrayNode a = (ArrayNode) n;
            for (int i = 0; i < a.size(); i++) a.set(i, walk(a.get(i)));
            return a;
        }
        if (n.isTextual()) return TextNode.valueOf(MaskUtil.mask(n.asText()));
        return n;
    }
}
