package com.crimenet.sharing;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "share_package")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SharePackage extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @Column(name = "recipient_id")
    private UUID recipientId;

    @Column(name = "recipient_email")
    private String recipientEmail;

    @Column(nullable = false)
    private String purpose;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private List<String> scope;  // document/evidence IDs

    @Column(nullable = false)
    @Builder.Default
    private String rights = "VIEW_ONLY";

    @Column(name = "watermark_enabled", nullable = false)
    @Builder.Default
    private boolean watermarkEnabled = true;

    @Column(name = "mfa_required", nullable = false)
    @Builder.Default
    private boolean mfaRequired = true;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "revoked_at")
    private Instant revokedAt;
}
