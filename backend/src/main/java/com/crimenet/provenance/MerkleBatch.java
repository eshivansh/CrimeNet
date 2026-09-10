package com.crimenet.provenance;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Represents a batch of audit events that have been Merkle-tree hashed and anchored.
 * Each batch captures a set of event IDs, the computed Merkle root, and the anchor status.
 */
@Entity
@Table(name = "merkle_batch")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MerkleBatch extends BaseEntity {

    @Column(name = "batch_number", nullable = false, unique = true)
    private long batchNumber;

    @Column(name = "merkle_root", nullable = false)
    private String merkleRoot;

    @Column(name = "event_count", nullable = false)
    private int eventCount;

    @Column(name = "first_event_id", nullable = false)
    private UUID firstEventId;

    @Column(name = "last_event_id", nullable = false)
    private UUID lastEventId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "event_hashes", nullable = false, columnDefinition = "jsonb")
    private List<String> eventHashes;

    @Column(name = "anchor_status", nullable = false)
    @Builder.Default
    private String anchorStatus = "PENDING"; // PENDING | ANCHORED | FAILED

    @Column(name = "anchor_type")
    private String anchorType; // TSA | LEDGER | MOCK

    @Column(name = "anchor_reference")
    private String anchorReference; // External proof reference

    @Column(name = "anchor_timestamp")
    private Instant anchorTimestamp;
}
