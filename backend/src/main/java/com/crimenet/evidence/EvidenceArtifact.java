package com.crimenet.evidence;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "evidence_artifact")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EvidenceArtifact extends BaseEntity {

    @Column(name = "evidence_id", nullable = false)
    private UUID evidenceId;

    @Column(name = "artifact_type", nullable = false)
    private String artifactType;  // PHOTO | VIDEO | AUDIO | BINARY | DOCUMENT

    @Column(name = "object_key", nullable = false)
    private String objectKey;

    @Column(name = "content_hash", nullable = false)
    private String contentHash;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "mime_type")
    private String mimeType;

    @Column
    private String description;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;
}
