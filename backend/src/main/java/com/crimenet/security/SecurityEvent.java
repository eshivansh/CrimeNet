package com.crimenet.security;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Security-specific audit subset — POLICY_DENIED, BREAK_GLASS_*, anomaly flags (§9).
 * Surfaced to a security dashboard with lower latency than general audit review.
 */
@Entity
@Table(name = "security_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityEvent extends BaseEntity {

    @Column(name = "event_type", nullable = false)
    private String eventType; // POLICY_DENIED | BREAK_GLASS_REQUESTED | ANOMALY_DETECTED | etc.

    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "case_id")
    private UUID caseId;

    @Column(name = "resource_id")
    private UUID resourceId;

    @Column(name = "severity", nullable = false)
    @Builder.Default
    private String severity = "MEDIUM"; // LOW | MEDIUM | HIGH | CRITICAL

    @Column(name = "description", nullable = false, length = 2000)
    private String description;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "resolved", nullable = false)
    @Builder.Default
    private boolean resolved = false;
}
