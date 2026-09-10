package com.crimenet.ai;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * The generated result from an AI job — immutable once completed.
 * Records the generated response for provenance and auditability.
 */
@Entity
@Table(name = "ai_result")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AIResult extends BaseEntity {

    @Column(name = "job_id", nullable = false, unique = true)
    private UUID jobId;

    @Column(name = "response_text", nullable = false, columnDefinition = "TEXT")
    private String responseText;

    @Column(name = "token_count")
    private int tokenCount;

    @Column(name = "confidence_score")
    private Double confidenceScore;
}
