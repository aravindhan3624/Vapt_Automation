package com.isolve.vapt.active;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-run settings the tester must supply to enable Phase 6 active checks. Nothing here has a
 * dangerous default: active testing stays OFF unless {@link #confirmedActiveTesting} is explicitly
 * set true AND a real approval reference is given that matches the project config and the
 * {@code VAPT_ACTIVE_APPROVAL} environment variable (see {@link ActiveTestGate}).
 */
public final class ActiveRunOptions {

    /** Must be set true by the tester for this run; false keeps every active check disabled. */
    public boolean confirmedActiveTesting = false;

    /** The written-approval reference for THIS active run (e.g. a ticket id). Must be non-placeholder. */
    public String approvalReference = "";

    /** Hosts (optionally host:port) that may be contacted. Anything else is refused. Must be non-empty. */
    public List<String> approvedHosts = new ArrayList<>();

    /** Checks the tester turned on. Empty = run nothing. Only read-only checks exist in this module. */
    public List<ActiveCheckType> enabledChecks = new ArrayList<>();

    /** Gentle pacing so tests never resemble a flood/brute force. */
    public long delayBetweenRequestsMs = 1_000;

    /** Hard ceiling on total requests this run may send, across all checks. */
    public int maxRequests = 200;

    /** Known OTHER object ids (e.g. a second test customer) used for read-only IDOR checks. */
    public List<String> otherObjectIds = new ArrayList<>();

    public boolean isEnabled(ActiveCheckType type) {
        return confirmedActiveTesting && enabledChecks.contains(type);
    }
}
