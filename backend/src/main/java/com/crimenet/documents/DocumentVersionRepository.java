package com.crimenet.documents;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DocumentVersionRepository extends JpaRepository<DocumentVersion, UUID> {

    List<DocumentVersion> findByDocumentIdOrderByVersionNoAsc(UUID documentId);

    Optional<DocumentVersion> findTopByDocumentIdOrderByVersionNoDesc(UUID documentId);

    @Query("SELECT dv FROM DocumentVersion dv WHERE dv.documentId = :documentId AND dv.versionNo = :versionNo")
    Optional<DocumentVersion> findByDocumentIdAndVersionNo(UUID documentId, int versionNo);

    long countByDocumentId(UUID documentId);

    List<DocumentVersion> findByUploadStatusAndCreatedAtBefore(String uploadStatus, java.time.Instant cutoff);

    List<DocumentVersion> findByContentHash(String contentHash);
}
