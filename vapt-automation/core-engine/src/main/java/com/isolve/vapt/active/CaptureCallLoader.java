package com.isolve.vapt.active;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads a recorder capture (.capture.jsonl) back into {@link RecordedCall}s so Phase 6 can re-send
 * safe, authorization-weakened variants. Reads the tester's own file; sends nothing.
 *
 * Note: recorder bodies are redacted, so a replayed body may carry ***REDACTED*** in some fields.
 * That is fine for the authorization checks (which only vary the credentials or the object id); any
 * field whose exact value matters is left to manual verification.
 */
public final class CaptureCallLoader {

    private static final ObjectMapper M = new ObjectMapper();

    private CaptureCallLoader() {
    }

    public static List<RecordedCall> load(Path captureJsonl) throws Exception {
        List<RecordedCall> out = new ArrayList<>();
        for (String line : Files.readAllLines(captureJsonl)) {
            if (line.isBlank()) continue;
            JsonNode n = M.readTree(line);
            RecordedCall c = new RecordedCall();
            c.method = n.path("method").asText("GET");
            String scheme = n.path("scheme").asText("https");
            String host = n.path("host").asText("");
            String path = n.path("path").asText("/");
            c.url = scheme + "://" + host + path;
            c.module = n.path("module").asText("");
            if (n.hasNonNull("requestBody")) c.plainBody = n.path("requestBody").asText();
            c.wasEncrypted = n.path("requestDecrypted").asBoolean(false);
            out.add(c);
        }
        return out;
    }
}
