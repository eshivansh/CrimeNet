package com.crimenet.policy;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.UUID;

/**
 * Resolved security context for the current request.
 * Built once per request from JWT + live DB lookups.
 */
@Data
@Builder
public class SecurityContext {
    private UUID userId;
    private UUID orgId;
    private String keycloakSubject;
    private String displayName;
    private UUID departmentId;
    private List<String> roles;
    private List<UUID> assignedCaseIds;
    private String mfaLevel;
    private String deviceTrust;
}
