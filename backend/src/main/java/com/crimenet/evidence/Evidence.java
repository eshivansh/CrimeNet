package com.crimenet.evidence;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "evidence")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Evidence extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "evidence_code", nullable = false, unique = true)
    private String evidenceCode;

    @Column
    private String title;

    @Column
    private String description;

    @Column(nullable = false)
    private String source;

    @Column(name = "source_device")
    private String sourceDevice;

    @Column(name = "collected_by", nullable = false)
    private UUID collectedBy;

    @Column(name = "collected_at", nullable = false)
    private Instant collectedAt;

    @Column
    private String location;

    @Column(name = "initial_hash", nullable = false)
    private String initialHash;

    @Column(nullable = false)
    @Builder.Default
    private String classification = "STANDARD";

    @Column(nullable = false)
    @Builder.Default
    private String status = "REGISTERED";
}
