package com.crimenet.retention;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RetentionService {

    private final LegalHoldRepository legalHoldRepository;
    private final UserService userService;
    private final PolicyEvaluationService policyService;
    private final AuditService auditService;
    private final com.crimenet.infrastructure.MinioStorageService minioStorageService;
    private final com.crimenet.documents.DocumentRepository documentRepository;
    private final com.crimenet.documents.DocumentVersionRepository documentVersionRepository;

    @Transactional
    public LegalHold applyLegalHold(UUID caseId, String reason) {
        policyService.enforceCasePermission(caseId, "LEGAL_HOLD", "MANAGE");

        AppUser currentUser = userService.getCurrentUser();

        LegalHold hold = LegalHold.builder()
                .caseId(caseId)
                .reason(reason)
                .appliedBy(currentUser.getId())
                .build();

        hold = legalHoldRepository.save(hold);

        auditService.record("LEGAL_HOLD_APPLIED", currentUser.getId(), hold.getId(), caseId,
                Map.of("reason", reason));

        log.info("Legal hold applied on case {} by {} — reason: {}", caseId, currentUser.getId(), reason);
        return hold;
    }

    @Transactional
    public LegalHold releaseLegalHold(UUID holdId, String releaseReason) {
        LegalHold hold = legalHoldRepository.findById(holdId)
                .orElseThrow(() -> new EntityNotFoundException("Legal hold not found: " + holdId));

        policyService.enforceCasePermission(hold.getCaseId(), "LEGAL_HOLD", "MANAGE");

        if (hold.getReleasedAt() != null) {
            throw new IllegalStateException("Legal hold already released: " + holdId);
        }

        AppUser currentUser = userService.getCurrentUser();
        hold.setReleasedBy(currentUser.getId());
        hold.setReleasedAt(Instant.now());
        hold.setReleaseReason(releaseReason);

        hold = legalHoldRepository.save(hold);

        auditService.record("LEGAL_HOLD_RELEASED", currentUser.getId(), holdId, hold.getCaseId(),
                Map.of("releaseReason", releaseReason));

        log.info("Legal hold {} released by {} — reason: {}", holdId, currentUser.getId(), releaseReason);
        return hold;
    }

    public boolean isCaseUnderHold(UUID caseId) {
        return legalHoldRepository.existsByCaseIdAndReleasedAtIsNull(caseId);
    }

    public List<LegalHold> getActiveHolds(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return legalHoldRepository.findByCaseIdAndReleasedAtIsNull(caseId);
    }

    @Transactional
    public void archiveDocument(UUID documentId) {
        com.crimenet.documents.Document doc = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found"));

        policyService.enforceCasePermission(doc.getCaseId(), "DOCUMENT", "MANAGE");

        if (isCaseUnderHold(doc.getCaseId())) {
            throw new IllegalStateException("Cannot archive document: Case is under an active legal hold.");
        }

        if (doc.isArchived()) {
            throw new IllegalStateException("Document is already archived.");
        }

        List<com.crimenet.documents.DocumentVersion> versions = documentVersionRepository.findByDocumentIdOrderByVersionNoAsc(documentId);

        for (com.crimenet.documents.DocumentVersion version : versions) {
            if ("COMMITTED".equals(version.getUploadStatus())) {
                minioStorageService.moveToArchive("crimenet-documents", version.getObjectKey(), version.getObjectKey());
            }
        }

        doc.setArchived(true);
        documentRepository.save(doc);

        AppUser currentUser = userService.getCurrentUser();
        auditService.record("DOCUMENT_ARCHIVED", currentUser.getId(), documentId, doc.getCaseId(), Map.of());
        log.info("Document {} archived by user {}", documentId, currentUser.getId());
    }
}
