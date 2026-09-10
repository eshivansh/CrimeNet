package com.crimenet.sharing;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Append-only access log for share packages.
 */
@Entity
@Table(name = "share_access")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ShareAccess extends BaseEntity {

    @Column(name = "share_package_id", nullable = false)
    private UUID sharePackageId;

    @Column(name = "accessed_by", nullable = false)
    private UUID accessedBy;

    @Column(nullable = false)
    private String action;  // VIEWED | DOWNLOADED | PRINTED

    @Column(name = "resource_id")
    private UUID resourceId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "accessed_at", nullable = false)
    @Builder.Default
    private Instant accessedAt = Instant.now();
}
