package com.crimenet.ai;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents an AI analysis or RAG query job.
 * AI is read/summarize/classify/suggest only — it has NO write path
 * to document, document_version, evidence, or custody_event tables (§15).
 */
@Entity
@Table(name = "ai_job")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AIJob extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "requested_by", nullable = false)
    private UUID requestedBy;

    @Column(name = "job_type", nullable = false)
    private String jobType; // RAG_QUERY | CLASSIFY | SUMMARIZE | ENTITY_EXTRACT

    @Column(name = "query_text", nullable = false, length = 4000)
    private String queryText;

    @Column(name = "model_name")
    private String modelName;

    @Column(name = "model_version")
    private String modelVersion;

    @Column(nullable = false)
    @Builder.Default
    private String status = "PENDING"; // PENDING | PROCESSING | COMPLETED | FAILED

    @Column(name = "completed_at")
    private Instant completedAt;
}
