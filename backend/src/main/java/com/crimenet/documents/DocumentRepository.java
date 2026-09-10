package com.crimenet.documents;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DocumentRepository extends JpaRepository<Document, UUID> {
    List<Document> findByCaseId(UUID caseId);
    Optional<Document> findByBusinessId(String businessId);
    boolean existsByBusinessId(String businessId);
}
