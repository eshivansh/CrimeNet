package com.crimenet.ai;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Tracks which document chunks/versions the AI actually retrieved and cited.
 * This is the core of AI provenance — proves exactly what data influenced the response.
 */
@Entity
@Table(name = "ai_reference")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AIReference extends BaseEntity {

    @Column(name = "result_id", nullable = false)
    private UUID resultId;

    @Column(name = "document_id", nullable = false)
    private UUID documentId;

    @Column(name = "document_version_id")
    private UUID documentVersionId;

    @Column(name = "chunk_text", columnDefinition = "TEXT")
    private String chunkText;

    @Column(name = "relevance_score")
    private Double relevanceScore;
}
