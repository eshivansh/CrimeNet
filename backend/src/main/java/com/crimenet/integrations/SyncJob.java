package com.crimenet.integrations;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Tracks synchronization jobs with external systems.
 */
@Entity
@Table(name = "sync_job")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SyncJob extends BaseEntity {

    @Column(name = "source_system", nullable = false)
    private String sourceSystem;

    @Column(name = "job_type", nullable = false)
    private String jobType; // FULL_SYNC | INCREMENTAL | SINGLE_RESOURCE

    @Column(nullable = false)
    @Builder.Default
    private String status = "PENDING"; // PENDING | RUNNING | COMPLETED | FAILED

    @Column(name = "records_processed")
    @Builder.Default
    private int recordsProcessed = 0;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "triggered_by")
    private UUID triggeredBy;
}
