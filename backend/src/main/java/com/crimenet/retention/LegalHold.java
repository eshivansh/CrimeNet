package com.crimenet.retention;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "legal_hold")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LegalHold extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(nullable = false)
    private String reason;

    @Column(name = "applied_by", nullable = false)
    private UUID appliedBy;

    @Column(name = "applied_at", nullable = false)
    @Builder.Default
    private Instant appliedAt = Instant.now();

    @Column(name = "released_by")
    private UUID releasedBy;

    @Column(name = "released_at")
    private Instant releasedAt;

    @Column(name = "release_reason")
    private String releaseReason;
}
