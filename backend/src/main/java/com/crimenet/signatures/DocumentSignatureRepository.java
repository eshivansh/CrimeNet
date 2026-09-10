package com.crimenet.signatures;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface DocumentSignatureRepository extends JpaRepository<DocumentSignature, UUID> {
    List<DocumentSignature> findByDocumentIdOrderBySignedAtDesc(UUID documentId);
    List<DocumentSignature> findByVersionIdOrderBySignedAtDesc(UUID versionId);
    List<DocumentSignature> findBySignerIdOrderBySignedAtDesc(UUID signerId);
}
