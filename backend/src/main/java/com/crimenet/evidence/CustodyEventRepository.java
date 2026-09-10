package com.crimenet.evidence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CustodyEventRepository extends JpaRepository<CustodyEvent, UUID> {

    List<CustodyEvent> findByEvidenceIdOrderByCreatedAtAsc(UUID evidenceId);

    Optional<CustodyEvent> findTopByEvidenceIdOrderByCreatedAtDesc(UUID evidenceId);

    long countByEvidenceId(UUID evidenceId);
}
