package com.crimenet.sharing;

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
public class ShareService {

    private final SharePackageRepository sharePackageRepository;
    private final com.crimenet.sharing.ShareAccessRepository shareAccessRepository;
    private final PolicyEvaluationService policyService;
    private final AuditService auditService;
    private final com.crimenet.infrastructure.MinioStorageService minioStorageService;
    private final com.crimenet.documents.DocumentVersionRepository documentVersionRepository;
    private final com.crimenet.documents.DocumentRepository documentRepository;
    private final UserService userService;

    @Transactional
    public SharePackage createShare(CreateShareRequest request) {
        policyService.enforceCasePermission(request.caseId(), "SHARE", "CREATE");

        AppUser currentUser = userService.getCurrentUser();

        SharePackage pkg = SharePackage.builder()
                .caseId(request.caseId())
                .createdBy(currentUser.getId())
                .recipientId(request.recipientId())
                .recipientEmail(request.recipientEmail())
                .purpose(request.purpose())
                .scope(request.scope())
                .rights(request.rights() != null ? request.rights() : "VIEW_ONLY")
                .watermarkEnabled(request.watermarkEnabled() != null ? request.watermarkEnabled() : true)
                .mfaRequired(request.mfaRequired() != null ? request.mfaRequired() : true)
                .expiresAt(request.expiresAt())
                .build();

        pkg = sharePackageRepository.save(pkg);

        auditService.record("SHARE_CREATED", currentUser.getId(), pkg.getId(), request.caseId(),
                Map.of("recipientId", String.valueOf(request.recipientId()),
                        "purpose", request.purpose(), "rights", pkg.getRights(),
                        "expiresAt", request.expiresAt().toString()));

        log.info("Share package created for case {} to recipient {}", request.caseId(), request.recipientId());
        return pkg;
    }

    @Transactional
    public SharePackage revokeShare(UUID shareId) {
        SharePackage pkg = sharePackageRepository.findById(shareId)
                .orElseThrow(() -> new EntityNotFoundException("Share package not found: " + shareId));

        policyService.enforceCaseAccess(pkg.getCaseId());

        AppUser currentUser = userService.getCurrentUser();
        pkg.setStatus("REVOKED");
        pkg.setRevokedAt(Instant.now());
        pkg = sharePackageRepository.save(pkg);

        auditService.record("SHARE_REVOKED", currentUser.getId(), shareId, pkg.getCaseId(),
                Map.of("revokedAt", Instant.now().toString()));

        log.info("Share package {} revoked by {}", shareId, currentUser.getId());
        return pkg;
    }

    public SharePackage getShare(UUID shareId) {
        return sharePackageRepository.findById(shareId)
                .orElseThrow(() -> new EntityNotFoundException("Share package not found: " + shareId));
    }

    public List<SharePackage> listSharesForCase(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return sharePackageRepository.findByCaseIdAndStatus(caseId, "ACTIVE");
    }

    public String generateDownloadUrl(UUID shareId, UUID documentVersionId, String mfaToken) {
        SharePackage pkg = getShare(shareId);

        if (!"ACTIVE".equals(pkg.getStatus()) || (pkg.getExpiresAt() != null && pkg.getExpiresAt().isBefore(Instant.now()))) {
            throw new IllegalStateException("Share link has expired or is revoked");
        }

        // Validate MFA if required
        if (pkg.isMfaRequired()) {
            if (mfaToken == null || mfaToken.isBlank()) {
                throw new SecurityException("MFA token is required to access this share package");
            }
            // Mock validation - in a real app this would verify against an MFA service/Keycloak
            if (!mfaToken.startsWith("MFA-")) {
                throw new SecurityException("Invalid MFA token");
            }
        }

        // Verify user is recipient or creator, or has case access
        AppUser currentUser = userService.getCurrentUser();
        if (!currentUser.getId().equals(pkg.getRecipientId()) && !currentUser.getId().equals(pkg.getCreatedBy())) {
            policyService.enforceCaseAccess(pkg.getCaseId());
        }

        com.crimenet.documents.DocumentVersion version = documentVersionRepository.findById(documentVersionId)
                .orElseThrow(() -> new EntityNotFoundException("Document version not found"));

        com.crimenet.documents.Document doc = documentRepository.findById(version.getDocumentId())
                .orElseThrow(() -> new EntityNotFoundException("Document not found"));

        if (!doc.getCaseId().equals(pkg.getCaseId())) {
            throw new IllegalArgumentException("Document does not belong to shared case");
        }

        if (pkg.getScope() != null && !pkg.getScope().isEmpty()) {
            boolean inScope = pkg.getScope().contains(doc.getId().toString())
                    || pkg.getScope().contains(documentVersionId.toString())
                    || (doc.getDocType() != null && pkg.getScope().contains(doc.getDocType()));
            if (!inScope) {
                throw new SecurityException("Requested document is not within the scope of this share package");
            }
        }

        // Generate short-lived pre-signed URL
        auditService.record("SHARE_DOWNLOADED", currentUser.getId(), documentVersionId, pkg.getCaseId(),
                Map.of("shareId", shareId.toString(), "watermarked", pkg.isWatermarkEnabled()));
                
        ShareAccess access = ShareAccess.builder()
                .sharePackageId(shareId)
                .accessedBy(currentUser.getId())
                .action("DOWNLOADED")
                .resourceId(documentVersionId)
                .build();
        shareAccessRepository.save(access);
        
        String url = minioStorageService.generatePresignedUrl("crimenet-documents", version.getObjectKey(), 300);
        
        // Append watermark directive for frontend
        if (pkg.isWatermarkEnabled()) {
            url += "&watermark=true&user=" + currentUser.getId();
        }
        
        return url;
    }

    public record CreateShareRequest(
            UUID caseId,
            UUID recipientId,
            String recipientEmail,
            String purpose,
            List<String> scope,
            String rights,
            Boolean watermarkEnabled,
            Boolean mfaRequired,
            Instant expiresAt
    ) {}
}
