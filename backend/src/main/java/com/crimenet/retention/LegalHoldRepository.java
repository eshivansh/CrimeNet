package com.crimenet.retention;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface LegalHoldRepository extends JpaRepository<LegalHold, UUID> {
    List<LegalHold> findByCaseIdAndReleasedAtIsNull(UUID caseId);
    boolean existsByCaseIdAndReleasedAtIsNull(UUID caseId);
}
