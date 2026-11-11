package com.isolve.vapt.active;

import com.isolve.vapt.config.ProjectConfig;

import java.util.List;
import java.util.Locale;

/**
 * The single safety gate for Phase 6. Active checks send real requests to the target, so this
 * gate fails CLOSED: {@link ActiveChecks} cannot be constructed without an {@link Authorization}
 * token, and the only way to get one is {@link #authorize}, which throws unless EVERY condition
 * holds:
 *
 *   1. The project config passed {@code ConfigLoader} (scope present, not a placeholder).
 *   2. The environment is not production (defence-in-depth: re-checked here).
 *   3. The tester set {@code confirmedActiveTesting = true} for this run.
 *   4. A real approval reference was given that is NOT a placeholder and MATCHES the
 *      {@code scope.approvalReference} recorded in the project config.
 *   5. The same reference is also present in the {@code VAPT_ACTIVE_APPROVAL} environment
 *      variable, so running active tests always needs a deliberate out-of-band step; it can
 *      never happen just because a config file was committed.
 *   6. At least one approved host is listed, and at least one check is enabled.
 *
 * The approval reference is recorded on the token purely so the report can state under which
 * authorization the active run was performed.
 */
public final class ActiveTestGate {

    public static final String APPROVAL_ENV_VAR = "VAPT_ACTIVE_APPROVAL";

    /** Opaque proof that the gate was passed. Required to build {@link ActiveChecks}. */
    public static final class Authorization {
        public final String approvalReference;
        public final String authorizedBy;
        public final String environment;
        public final List<String> approvedHosts;

        private Authorization(String approvalReference, String authorizedBy, String environment, List<String> approvedHosts) {
            this.approvalReference = approvalReference;
            this.authorizedBy = authorizedBy;
            this.environment = environment;
            this.approvedHosts = List.copyOf(approvedHosts);
        }
    }

    private ActiveTestGate() {
    }

    public static Authorization authorize(ProjectConfig config, ActiveRunOptions options) {
        return authorize(config, options, System.getenv(APPROVAL_ENV_VAR));
    }

    /** Package-visible for tests: the environment value is injected rather than read from the OS. */
    static Authorization authorize(ProjectConfig config, ActiveRunOptions options, String envApproval) {
        if (config == null || config.getScope() == null) {
            throw new SecurityException("Active testing refused: project config has no authorization scope.");
        }
        String env = config.getEnvironment() == null ? "" : config.getEnvironment().toUpperCase(Locale.ROOT);
        if (env.contains("PROD")) {
            throw new SecurityException("Active testing refused: environment '" + config.getEnvironment()
                    + "' looks like production.");
        }
        if (options == null || !options.confirmedActiveTesting) {
            throw new SecurityException("Active testing refused: confirmedActiveTesting is not set for this run. "
                    + "Active checks stay off until the tester explicitly confirms written approval.");
        }
        String ref = options.approvalReference == null ? "" : options.approvalReference.trim();
        if (isBlankOrPlaceholder(ref)) {
            throw new SecurityException("Active testing refused: no real approvalReference was supplied.");
        }
        String scopeRef = config.getScope().getApprovalReference() == null ? "" : config.getScope().getApprovalReference().trim();
        if (!ref.equals(scopeRef)) {
            throw new SecurityException("Active testing refused: the run's approvalReference does not match the "
                    + "approvalReference recorded in the project config scope.");
        }
        if (envApproval == null || !ref.equals(envApproval.trim())) {
            throw new SecurityException("Active testing refused: the " + APPROVAL_ENV_VAR + " environment variable "
                    + "is not set to the same approval reference. Set it deliberately to enable this run.");
        }
        if (options.approvedHosts == null || options.approvedHosts.isEmpty()) {
            throw new SecurityException("Active testing refused: no approved hosts were given.");
        }
        if (options.enabledChecks == null || options.enabledChecks.isEmpty()) {
            throw new SecurityException("Active testing refused: no checks were enabled.");
        }
        return new Authorization(ref, config.getScope().getAuthorizedBy(), config.getEnvironment(), options.approvedHosts);
    }

    private static boolean isBlankOrPlaceholder(String s) {
        if (s == null || s.trim().isEmpty()) return true;
        String u = s.toUpperCase(Locale.ROOT);
        return u.contains("<<") || u.contains("FILL ME") || u.equals("TODO") || u.equals("NONE");
    }
}
