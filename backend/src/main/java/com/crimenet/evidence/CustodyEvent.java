package com.crimenet.evidence;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Append-only custody event — hash-linked chain for tamper-evident custody trail.
 * DB trigger prevents UPDATE and DELETE.
 */
@Entity
@Table(name = "custody_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustodyEvent extends BaseEntity {

    @Column(name = "evidence_id", nullable = false)
    private UUID evidenceId;

    @Column(name = "artifact_id")
    private UUID artifactId;

    @Column(name = "from_actor")
    private UUID fromActor;

    @Column(name = "to_actor", nullable = false)
    private UUID toActor;

    @Column(nullable = false)
    private String action;  // REGISTERED | TRANSFERRED | ANALYZED | STORED | PRESENTED | RETURNED | DISPOSED

    @Column
    private String purpose;

    @Column
    private String location;

    @Column
    private String notes;

    @Column(name = "event_hash", nullable = false)
    private String eventHash;

    @Column(name = "previous_event_id")
    private UUID previousEventId;

    @Column(name = "previous_event_hash")
    private String previousEventHash;

    @Column
    private String signature;
}
