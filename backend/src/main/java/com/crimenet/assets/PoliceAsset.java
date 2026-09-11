package com.crimenet.assets;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "police_asset")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PoliceAsset extends BaseEntity {

    @Column(name = "case_id")
    private UUID caseId;

    /**
     * Owning organization.
     *
     * <p>The table had no tenant column at all, and neither the read paths nor the
     * controller applied any scoping — so any authenticated user of any agency could
     * enumerate every firearm, bodycam and vehicle in the system together with its current
     * custodian, badge number and linked case id, which also leaked case participation.
     */
    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "asset_tag", nullable = false, unique = true)
    private String assetTag;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String category; // WEAPON, BODYCAM, VEHICLE, COMMUNICATION, FORENSIC_KIT

    @Column(nullable = false)
    @Builder.Default
    private String status = "AVAILABLE"; // AVAILABLE, ISSUED, IN_FIELD, MAINTENANCE, DECOMMISSIONED

    @Column(name = "custodian_id")
    private UUID custodianId;

    @Column(name = "custodian_badge")
    private String custodianBadge;

    @Column
    private String department;

    @Column(name = "assigned_at")
    private Instant assignedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(name = "created_by")
    private UUID createdBy;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
