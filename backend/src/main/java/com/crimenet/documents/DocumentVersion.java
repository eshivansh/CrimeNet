package com.crimenet.documents;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "document_version",
       uniqueConstraints = @UniqueConstraint(columnNames = {"document_id", "version_no"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentVersion extends BaseEntity {

    @Column(name = "document_id", nullable = false)
    private UUID documentId;

    @Column(name = "version_no", nullable = false)
    private int versionNo;

    @Column(name = "content_hash", nullable = false)
    private String contentHash;

    @Column(name = "object_key", nullable = false)
    private String objectKey;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "mime_type", nullable = false)
    private String mimeType;

    @Column(name = "upload_status", nullable = false)
    @Builder.Default
    private String uploadStatus = "PENDING";

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;
}
