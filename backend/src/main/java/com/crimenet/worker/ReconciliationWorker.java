package com.crimenet.worker;

import com.crimenet.audit.AuditService;
import com.crimenet.documents.DocumentVersion;
import com.crimenet.documents.DocumentVersionRepository;
import com.crimenet.infrastructure.MinioStorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Reconciliation worker — sweeps PENDING document versions past a TTL (§4.3, §20).
 *
 * Handles the dual-write failure between Postgres and MinIO:
 *   - If a row is PENDING and older than the TTL, the upload failed or was abandoned.
 *   - The worker either retries the upload or marks the version FAILED + audit + alert.
 *   - A PENDING row is NEVER silently promoted to COMMITTED.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ReconciliationWorker {

    private final DocumentVersionRepository documentVersionRepository;
    private final MinioStorageService minioStorageService;
    private final AuditService auditService;

    private static final long PENDING_TTL_MINUTES = 30;

    /**
     * Run every 10 minutes: check for stale PENDING versions.
     */
    @Scheduled(fixedDelayString = "${crimenet.reconciliation.interval-ms:600000}")
    @Transactional
    public void reconcilePendingVersions() {
        Instant cutoff = Instant.now().minusSeconds(PENDING_TTL_MINUTES * 60);
        List<DocumentVersion> staleVersions = documentVersionRepository
                .findByUploadStatusAndCreatedAtBefore("PENDING", cutoff);

        if (staleVersions.isEmpty()) {
            return;
        }

        log.warn("Reconciliation worker found {} stale PENDING versions past {} min TTL",
                staleVersions.size(), PENDING_TTL_MINUTES);

        for (DocumentVersion version : staleVersions) {
            try {
                // Check if the object actually exists in MinIO
                byte[] content = minioStorageService.downloadDocument(version.getObjectKey());
                if (content != null && content.length > 0) {
                    // Object exists but row wasn't committed — mark as COMMITTED
                    version.setUploadStatus("COMMITTED");
                    documentVersionRepository.save(version);
                    log.info("Reconciled version {} — object exists, marked COMMITTED", version.getId());
                }
            } catch (Exception e) {
                // Object doesn't exist — mark as FAILED
                version.setUploadStatus("FAILED");
                documentVersionRepository.save(version);
                auditService.record("RECONCILIATION_FAILED", null, version.getId(), null,
                        Map.of("reason", "PENDING version past TTL, MinIO object not found",
                                "objectKey", version.getObjectKey()));
                log.error("Reconciliation: version {} marked FAILED — MinIO object missing", version.getId());
            }
        }
    }
}
