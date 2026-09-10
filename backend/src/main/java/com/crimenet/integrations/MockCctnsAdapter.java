package com.crimenet.integrations;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Mock CCTNS adapter returning realistic sample FIR data.
 */
@Slf4j
@Component
public class MockCctnsAdapter implements ExternalSystemAdapter {

    @Override
    public String getSystemName() {
        return "CCTNS";
    }

    @Override
    public Map<String, Object> fetchReference(String externalId) {
        log.info("[MOCK-CCTNS] Fetching reference: {}", externalId);
        return Map.of(
                "source", "CCTNS",
                "externalId", externalId,
                "firNumber", "FIR-2026-UP-" + externalId,
                "policeStation", "Cyber Crime Cell, Lucknow",
                "sections", "IT Act Section 66C, 66D; IPC Section 420",
                "status", "UNDER_INVESTIGATION",
                "io", "SI Rajesh Kumar",
                "registeredAt", "2026-03-15T10:30:00Z",
                "mock", true
        );
    }

    @Override
    public Map<String, Object> pushReference(String resourceType, String resourceId, Map<String, Object> data) {
        log.info("[MOCK-CCTNS] Pushing reference: {} / {}", resourceType, resourceId);
        return Map.of("status", "ACCEPTED", "cctnsRefId", "CCTNS-REF-" + resourceId, "mock", true);
    }

    @Override
    public boolean healthCheck() {
        log.debug("[MOCK-CCTNS] Health check: OK");
        return true;
    }
}
