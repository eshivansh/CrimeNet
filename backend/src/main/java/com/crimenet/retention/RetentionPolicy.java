package com.crimenet.retention;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Defines retention policies for document types within an organization (§12).
 * LegalHold overrides retention policy — held items cannot be disposed regardless of policy.
 */
@Entity
@Table(name = "retention_policy")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RetentionPolicy extends BaseEntity {

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "doc_type", nullable = false)
    private String docType; // FIR | CHARGESHEET | FORENSIC_REPORT | etc.

    @Column(name = "retention_years", nullable = false)
    private int retentionYears;

    @Column(name = "archive_after_years", nullable = false)
    private int archiveAfterYears;

    @Column(name = "requires_approval_for_disposition", nullable = false)
    @Builder.Default
    private boolean requiresApprovalForDisposition = true;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE"; // ACTIVE | INACTIVE
}
