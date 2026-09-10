package com.crimenet.integrations;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Mock ICJS adapter returning realistic sample payloads.
 */
@Slf4j
@Component
public class MockIcjsAdapter implements ExternalSystemAdapter {

    @Override
    public String getSystemName() {
        return "ICJS";
    }

    @Override
    public Map<String, Object> fetchReference(String externalId) {
        log.info("[MOCK-ICJS] Fetching reference: {}", externalId);
        return Map.of(
                "source", "ICJS",
                "externalId", externalId,
                "status", "ACTIVE",
                "caseType", "CRIMINAL",
                "court", "District Court, Lucknow",
                "nextHearing", "2026-10-15",
                "judge", "Hon. Principal Sessions Judge",
                "mock", true
        );
    }

    @Override
    public Map<String, Object> pushReference(String resourceType, String resourceId, Map<String, Object> data) {
        log.info("[MOCK-ICJS] Pushing reference: {} / {}", resourceType, resourceId);
        return Map.of("status", "ACCEPTED", "icjsRefId", "ICJS-REF-" + resourceId, "mock", true);
    }

    @Override
    public boolean healthCheck() {
        log.debug("[MOCK-ICJS] Health check: OK");
        return true;
    }
}
