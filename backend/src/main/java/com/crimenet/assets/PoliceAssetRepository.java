package com.crimenet.assets;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PoliceAssetRepository extends JpaRepository<PoliceAsset, UUID> {

    Optional<PoliceAsset> findByAssetTag(String assetTag);

    List<PoliceAsset> findByCaseId(UUID caseId);

    List<PoliceAsset> findByCustodianId(UUID custodianId);

    List<PoliceAsset> findByStatus(String status);

    List<PoliceAsset> findByCategory(String category);

    @Query("""
        SELECT a FROM PoliceAsset a
        WHERE (:category IS NULL OR a.category = :category)
          AND (:status IS NULL OR a.status = :status)
          AND (:caseId IS NULL OR a.caseId = :caseId)
          AND (:custodianId IS NULL OR a.custodianId = :custodianId)
        ORDER BY a.createdAt DESC
    """)
    List<PoliceAsset> searchAssets(
            @Param("category") String category,
            @Param("status") String status,
            @Param("caseId") UUID caseId,
            @Param("custodianId") UUID custodianId
    );
}
