package com.crimenet.documents;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "document")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Document extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "business_id", nullable = false, unique = true)
    private String businessId;

    @Column(name = "doc_type", nullable = false)
    private String docType;

    @Column
    private String title;

    @Column(nullable = false)
    @Builder.Default
    private String classification = "STANDARD";

    @Column(name = "current_version_id")
    private UUID currentVersionId;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "is_archived", nullable = false)
    @Builder.Default
    private boolean isArchived = false;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    // Hibernate includes updated_at in the INSERT; without this it writes NULL and the
    // NOT NULL constraint rejects the row before the column DEFAULT can apply.
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
