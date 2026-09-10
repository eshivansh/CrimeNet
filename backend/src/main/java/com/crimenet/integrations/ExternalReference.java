package com.crimenet.integrations;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Maps CrimeNet resources to their external system identifiers.
 * Metadata-first federation — store external IDs locally, fetch content only when needed (§16).
 */
@Entity
@Table(name = "external_reference",
       uniqueConstraints = @UniqueConstraint(columnNames = {"source_system", "external_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ExternalReference extends BaseEntity {

    @Column(name = "source_system", nullable = false)
    private String sourceSystem; // CCTNS | ICJS | ESAKSHYA | etc.

    @Column(name = "external_id", nullable = false)
    private String externalId;

    @Column(name = "resource_type", nullable = false)
    private String resourceType; // DOCUMENT | EVIDENCE | CASE

    @Column(name = "local_resource_id", nullable = false)
    private UUID localResourceId;

    @Column(name = "sync_status")
    @Builder.Default
    private String syncStatus = "SYNCED"; // SYNCED | STALE | FAILED
}
