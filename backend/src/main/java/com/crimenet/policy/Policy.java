package com.crimenet.policy;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Versioned ABAC policy rule definition (§3).
 * Stores declarative policy rules that the PolicyEvaluationService uses
 * to make authorization decisions. Admin-only, version-tracked.
 */
@Entity
@Table(name = "policy")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Policy extends BaseEntity {

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "policy_name", nullable = false)
    private String policyName;

    @Column(name = "resource_type", nullable = false)
    private String resourceType; // CASE | DOCUMENT | EVIDENCE | SHARE

    @Column(name = "action", nullable = false)
    private String action; // CREATE | READ | UPDATE | DELETE | SHARE | DOWNLOAD

    @Column(name = "condition_expression", columnDefinition = "TEXT")
    private String conditionExpression; // e.g. "role IN ('INVESTIGATOR','SUPERVISOR') AND case_assigned = true"

    @Column(name = "effect", nullable = false)
    @Builder.Default
    private String effect = "ALLOW"; // ALLOW | DENY

    @Column(name = "priority")
    @Builder.Default
    private int priority = 0; // Higher priority rules evaluated first

    @Column(name = "version", nullable = false)
    @Builder.Default
    private int version = 1;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE"; // ACTIVE | DEPRECATED

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;
}
