package com.crimenet.security;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Short-lived break-glass grant — emergency access for critical situations (§11).
 *
 * Rules:
 *   - Reason required
 *   - Step-up MFA required (validated at controller level)
 *   - Time-boxed (default 30 minutes)
 *   - View-only, watermarked
 *   - Automatic expiry via scheduled job
 *   - Mandatory supervisor notification + audit events
 */
@Entity
@Table(name = "break_glass_grant")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BreakGlassGrant extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "granted_to", nullable = false)
    private UUID grantedTo;

    @Column(nullable = false, length = 1000)
    private String reason;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE"; // ACTIVE | EXPIRED | REVOKED

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "supervisor_id")
    private UUID supervisorId;

    @Column(name = "supervisor_notified", nullable = false)
    @Builder.Default
    private boolean supervisorNotified = false;
}
