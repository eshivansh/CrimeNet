package com.crimenet.workflow;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Tracks the lifecycle state transitions for case-related resources (§12).
 * Maps the retention lifecycle: ACTIVE → SEALED → ARCHIVED → RETENTION_REVIEW → DISPOSITION
 * Legal holds block the DISPOSITION transition entirely.
 */
@Entity
@Table(name = "workflow_transition")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WorkflowTransition extends BaseEntity {

    @Column(name = "resource_type", nullable = false)
    private String resourceType; // CASE | DOCUMENT | EVIDENCE

    @Column(name = "resource_id", nullable = false)
    private UUID resourceId;

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "from_status", nullable = false)
    private String fromStatus;

    @Column(name = "to_status", nullable = false)
    private String toStatus;

    @Column(name = "transitioned_by", nullable = false)
    private UUID transitionedBy;

    @Column(name = "transitioned_at", nullable = false)
    @Builder.Default
    private Instant transitionedAt = Instant.now();

    @Column(name = "reason")
    private String reason;

    @Column(name = "approval_required")
    @Builder.Default
    private boolean approvalRequired = false;

    @Column(name = "approved_by")
    private UUID approvedBy;
}
