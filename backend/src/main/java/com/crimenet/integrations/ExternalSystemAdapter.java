package com.crimenet.integrations;

import java.util.Map;

/**
 * Common interface for all external system adapters (§16).
 * Mock adapters are swapped for real ones via Spring profiles — no application code changes.
 */
public interface ExternalSystemAdapter {

    /**
     * Unique system identifier (e.g., ICJS, CCTNS, ESAKSHYA).
     */
    String getSystemName();

    /**
     * Fetch a reference/record from the external system.
     */
    Map<String, Object> fetchReference(String externalId);

    /**
     * Push a reference to the external system.
     */
    Map<String, Object> pushReference(String resourceType, String resourceId, Map<String, Object> data);

    /**
     * Check if the external system is reachable.
     */
    boolean healthCheck();
}
