package com.crimenet.cases;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CaseAssignmentRepository extends JpaRepository<CaseAssignment, UUID> {

    List<CaseAssignment> findByCaseIdAndRevokedAtIsNull(UUID caseId);

    List<CaseAssignment> findByUserIdAndRevokedAtIsNull(UUID userId);

    boolean existsByCaseIdAndUserIdAndRevokedAtIsNull(UUID caseId, UUID userId);

    @Query("SELECT ca.caseId FROM CaseAssignment ca WHERE ca.userId = :userId AND ca.revokedAt IS NULL")
    List<UUID> findActiveCaseIdsByUserId(UUID userId);
}
