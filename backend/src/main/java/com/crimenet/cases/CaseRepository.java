package com.crimenet.cases;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CaseRepository extends JpaRepository<CaseRecord, UUID> {
    Optional<CaseRecord> findByCaseNumber(String caseNumber);
    boolean existsByCaseNumber(String caseNumber);
    Page<CaseRecord> findByOrgIdAndStatus(UUID orgId, String status, Pageable pageable);
    Page<CaseRecord> findByOrgId(UUID orgId, Pageable pageable);
}
