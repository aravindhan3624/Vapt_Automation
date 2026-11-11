package com.isolve.vapt.active;

/**
 * Sends one {@link ActiveRequest} to the real target and returns the {@link ActiveResponse}.
 * The implementation (project-specific: e.g. CKYC re-encrypts the body, routes through REST
 * Assured, decrypts the reply) lives outside core-engine, so the engine stays project-independent.
 *
 * Implementations MUST honour {@link ActiveRequest.Auth} exactly (NONE means send no credentials)
 * and MUST only ever perform the single HTTP call described — never retries that could multiply
 * load, never follow-up writes.
 */
@FunctionalInterface
public interface ActiveTarget {
    ActiveResponse send(ActiveRequest request) throws Exception;
}
