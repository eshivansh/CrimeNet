package com.crimenet.documents;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Records a terminal upload failure so that it survives the rollback of the upload.
 *
 * <p>{@code DocumentService} used to set {@code uploadStatus} to FAILED, save, and then
 * throw — all inside one transaction, which rolled the saved row back together with the
 * document row. The outbox states the design documents were therefore unobservable, the
 * reconciliation sweep had nothing to find, and a rejected malware upload left no database
 * trace at all, making forensic review of rejected uploads impossible.
 *
 * <p>REQUIRES_NEW, in its own bean so the proxy actually applies it — the same reason
 * {@code AuditService} is structured this way.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UploadFailureRecorder {

    private final DocumentVersionRepository documentVersionRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID versionId, String status, String reason) {
        try {
            documentVersionRepository.findById(versionId).ifPresent(version -> {
                version.setUploadStatus(status);
                documentVersionRepository.save(version);
            });
            log.warn("UPLOAD_FAILED version={} status={} reason={}", versionId, status, reason);
        } catch (RuntimeException e) {
            // Never let bookkeeping mask the original failure.
            log.error("Could not record upload failure for version {}: {}", versionId, e.getMessage());
        }
    }
}
