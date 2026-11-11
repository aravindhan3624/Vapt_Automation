package com.isolve.vapt.ckyc.active;

import org.testng.SkipException;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * IDE launcher for the Phase 6 CKYC active checks (approval-gated, read-only). Run from the gutter
 * in IntelliJ with, for example, VM options:
 *
 *   -Dvapt.config=projects/ckyc/config/ckyc-config.yaml
 *   -Dvapt.capture=C:\captures\CKYC-7.0\...capture.jsonl
 *   -Dvapt.approval=ISOLVE-VAPT-CKYC-2026-001
 *   -Dvapt.checks=UNAUTH_DOCUMENT_ACCESS
 *
 * and the environment variable VAPT_ACTIVE_APPROVAL set to the same reference (the gate requires it).
 * For the encrypted API checks also set the env var VAPT_SERVER_PUBLIC_KEY (or -Dvapt.serverKey) and
 * VAPT_SESSION_VALUE. The name avoids this module's surefire patterns (*TestRunner / active/*IT), so a
 * plain {@code mvn} build never runs it; it skips unless config + capture + approval are given.
 * Equivalent to {@code tools/active-checks.ps1}.
 *
 * Note: the gate calls System.exit on refusal, which ends the IDE run with a clear message - that is
 * expected, nothing was sent.
 */
public class RunActiveChecks {

    @Test
    public void run() throws Exception {
        String config = System.getProperty("vapt.config", "").trim();
        String capture = System.getProperty("vapt.capture", "").trim();
        String approval = System.getProperty("vapt.approval", "").trim();
        if (config.isEmpty() || capture.isEmpty() || approval.isEmpty()) {
            throw new SkipException("Set -Dvapt.config, -Dvapt.capture and -Dvapt.approval (and the "
                    + "VAPT_ACTIVE_APPROVAL environment variable to the same reference) to run the active checks from the IDE.");
        }
        List<String> a = new ArrayList<>(List.of(
                "--config", config,
                "--capture", capture,
                "--approval", approval,
                "--checks", System.getProperty("vapt.checks", "UNAUTH_DOCUMENT_ACCESS")));
        addIfSet(a, "--hosts", "vapt.hosts");
        addIfSet(a, "--other-ids", "vapt.otherIds");
        addIfSet(a, "--out", "vapt.out");
        CkycActiveRunner.main(a.toArray(new String[0]));
    }

    private static void addIfSet(List<String> a, String flag, String prop) {
        String v = System.getProperty(prop, "").trim();
        if (!v.isEmpty()) {
            a.add(flag);
            a.add(v);
        }
    }
}
