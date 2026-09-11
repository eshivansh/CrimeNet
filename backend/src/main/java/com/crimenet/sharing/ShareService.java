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
    private final com.crimenet.identity.AppUserRepository appUserRepository;
    private final com.crimenet.security.StepUpVerificationService stepUpVerificationService;
    private final com.crimenet.security.SecurityEventService securityEventService;

    /** Ceiling on how long a share package may live, whatever the caller asked for. */
    @org.springframework.beans.factory.annotation.Value("${crimenet.sharing.max-lifetime-days:30}")
    private long maxLifetimeDays;

    /** Operator acknowledgement that VIEW_ONLY recipients receive unwatermarked originals. */
    @org.springframework.beans.factory.annotation.Value("${crimenet.sharing.allow-unwatermarked-view-only:true}")
    private boolean allowUnwatermarkedViewOnly;

    private static final java.util.Set<String> VALID_RIGHTS =
            java.util.Set.of("VIEW_ONLY", "DOWNLOAD");

    @Transactional
    public SharePackage createShare(CreateShareRequest request) {
        policyService.enforceCasePermission(request.caseId(), "SHARE", "CREATE");

        AppUser currentUser = userService.getCurrentUser();

        // The recipient, the expiry and the rights all used to be copied from the request
        // body unchecked, which let a share name any user in any organization, never
        // expire, and carry an empty scope that downstream treated as "everything".
        AppUser recipient = appUserRepository.findById(request.recipientId())
                .orElseThrow(() -> new EntityNotFoundException("Recipient not found: " + request.recipientId()));

        if (!currentUser.getOrgId().equals(recipient.getOrgId())) {
            securityEventService.denied("SHARE_CROSS_TENANT_RECIPIENT", currentUser.getId(), request.caseId(),
                    "Attempted to share case material with a recipient in organization " + recipient.getOrgId());
            throw new org.springframework.security.access.AccessDeniedException(
                    "Cross-organization sharing must go through a formal transfer, not a share package.");
        }
        if (!"ACTIVE".equalsIgnoreCase(recipient.getStatus())) {
            throw new IllegalArgumentException(
                    "Recipient " + recipient.getId() + " is " + recipient.getStatus() + " and cannot receive shares.");
        }

        Instant expiresAt = clampExpiry(request.expiresAt());

        String rights = request.rights() != null ? request.rights().toUpperCase(java.util.Locale.ROOT) : "VIEW_ONLY";
        if (!VALID_RIGHTS.contains(rights)) {
            throw new IllegalArgumentException("rights must be one of " + VALID_RIGHTS);
        }

        if (request.scope() == null || request.scope().isEmpty()) {
            throw new IllegalArgumentException(
                    "An explicit scope is required: list the document ids, version ids or document types "
                            + "this package covers. An empty scope is treated as deny-all, not allow-all.");
        }

        SharePackage pkg = SharePackage.builder()
                .caseId(request.caseId())
                .createdBy(currentUser.getId())
                .recipientId(request.recipientId())
                .recipientEmail(request.recipientEmail())
                .purpose(request.purpose())
                .scope(request.scope())
                .rights(rights)
                // Watermarking and step-up are organizational policy, not caller preference.
                .watermarkEnabled(true)
                .mfaRequired(true)
                .expiresAt(expiresAt)
                .build();

        pkg = sharePackageRepository.save(pkg);

        auditService.record("SHARE_CREATED", currentUser.getId(), pkg.getId(), request.caseId(),
                Map.of("recipientId", String.valueOf(request.recipientId()),
                        "purpose", request.purpose(), "rights", pkg.getRights(),
                        "scopeEntries", String.valueOf(request.scope().size()),
                        "expiresAt", expiresAt.toString()));

        log.info("Share package created for case {} to recipient {}, expires {}",
                request.caseId(), request.recipientId(), expiresAt);
        return pkg;
    }

    private Instant clampExpiry(Instant requested) {
        Instant ceiling = Instant.now().plus(java.time.Duration.ofDays(maxLifetimeDays));
        if (requested == null) {
            throw new IllegalArgumentException(
                    "expiresAt is required; a share package with no expiry never expires.");
        }
        if (requested.isBefore(Instant.now())) {
            throw new IllegalArgumentException("expiresAt is in the past.");
        }
        if (requested.isAfter(ceiling)) {
            log.info("Requested share expiry {} exceeds the {}-day ceiling; clamped to {}",
                    requested, maxLifetimeDays, ceiling);
            return ceiling;
        }
        return requested;
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
        SharePackage pkg = sharePackageRepository.findById(shareId)
                .orElseThrow(() -> new EntityNotFoundException("Share package not found: " + shareId));

        AppUser currentUser = userService.getCurrentUser();
        // Guard against BOLA: caller must be recipient, creator, or have authorized case access
        if (!currentUser.getId().equals(pkg.getRecipientId()) && !currentUser.getId().equals(pkg.getCreatedBy())) {
            policyService.enforceCaseAccess(pkg.getCaseId());
        }
        return pkg;
    }

    public List<SharePackage> listSharesForCase(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return sharePackageRepository.findByCaseIdAndStatus(caseId, "ACTIVE");
    }

    /**
     * Read-write on purpose: this method persists a {@link ShareAccess} row. Inheriting
     * the class-level {@code readOnly = true} put Hibernate in MANUAL flush mode, so that
     * insert was silently discarded and the share-access forensic trail was empty.
     */
    @Transactional
    public ShareDownloadResponse generateDownloadUrl(UUID shareId, UUID documentVersionId) {
        SharePackage pkg = getShare(shareId);

        // A null expiresAt used to mean "never expires"; new packages cannot be created
        // that way, and any legacy row without one is treated as expired.
        if (!"ACTIVE".equals(pkg.getStatus()) || pkg.getExpiresAt() == null
                || pkg.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalStateException("Share link has expired or is revoked");
        }

        if (pkg.isMfaRequired()) {
            stepUpVerificationService.requireStepUp("download from share package " + shareId);
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

        // Empty scope is deny-all. It previously fell through as allow-all, which turned
        // an unset field into unrestricted access to every document on the case.
        if (pkg.getScope() == null || pkg.getScope().isEmpty()) {
            securityEventService.denied("SHARE_EMPTY_SCOPE_DOWNLOAD", currentUser.getId(), pkg.getCaseId(),
                    "Share package " + shareId + " has no scope; download refused");
            throw new org.springframework.security.access.AccessDeniedException(
                    "This share package defines no scope and grants access to nothing.");
        }
        boolean inScope = pkg.getScope().contains(doc.getId().toString())
                || pkg.getScope().contains(documentVersionId.toString())
                || (doc.getDocType() != null && pkg.getScope().contains(doc.getDocType()));
        if (!inScope) {
            securityEventService.denied("SHARE_OUT_OF_SCOPE", currentUser.getId(), pkg.getCaseId(),
                    "Requested document " + doc.getId() + " is outside share package " + shareId);
            throw new org.springframework.security.access.AccessDeniedException(
                    "Requested document is not within the scope of this share package");
        }

        // VIEW_ONLY promises a restriction the system cannot deliver: a pre-signed URL is
        // the unmodified original, and no watermarking code exists. Rather than hand out
        // an unwatermarked original under a watermark:true flag the client is trusted to
        // honour, VIEW_ONLY is refused unless the operator has explicitly accepted that.
        boolean downloadRights = "DOWNLOAD".equals(pkg.getRights());
        if (!downloadRights && !allowUnwatermarkedViewOnly) {
            throw new UnsupportedOperationException(
                    "This package grants VIEW_ONLY rights, and server-side watermarked streaming "
                            + "is not implemented. Issue a DOWNLOAD package, or set "
                            + "crimenet.sharing.allow-unwatermarked-view-only=true to accept that "
                            + "VIEW_ONLY recipients receive unwatermarked originals.");
        }
        if (!downloadRights) {
            log.warn("SHARE_VIEW_ONLY_UNWATERMARKED: package {} served an unwatermarked original to {}",
                    shareId, currentUser.getId());
        }

        auditService.record("SHARE_DOWNLOADED", currentUser.getId(), documentVersionId, pkg.getCaseId(),
                Map.of("shareId", shareId.toString(),
                        "rights", pkg.getRights(),
                        // What actually happened, not what the package requested.
                        "watermarkApplied", false));

        ShareAccess access = ShareAccess.builder()
                .sharePackageId(shareId)
                .accessedBy(currentUser.getId())
                .action("DOWNLOADED")
                .resourceId(documentVersionId)
                .build();
        shareAccessRepository.save(access);

        String url = minioStorageService.generatePresignedUrl(
                "crimenet-documents", version.getObjectKey(), 300, doc.getTitle());

        return new ShareDownloadResponse(
                url,
                // The response no longer claims a watermark that was never applied.
                false,
                currentUser.getId().toString()
        );
    }

    public record ShareDownloadResponse(
            String downloadUrl,
            boolean watermark,
            String watermarkUser
    ) {}

    /**
     * watermarkEnabled and mfaRequired are deliberately absent: they are organizational
     * policy, and letting the caller set mfaRequired=false was a way to opt out of the
     * step-up requirement on the package they were creating.
     */
    public record CreateShareRequest(
            @jakarta.validation.constraints.NotNull(message = "caseId is required")
            UUID caseId,

            @jakarta.validation.constraints.NotNull(message = "recipientId is required")
            UUID recipientId,

            @jakarta.validation.constraints.Email(message = "recipientEmail must be a valid address")
            String recipientEmail,

            @jakarta.validation.constraints.NotBlank(message = "A purpose is required for the disclosure record")
            @jakarta.validation.constraints.Size(max = 1000)
            String purpose,

            @jakarta.validation.constraints.NotEmpty(message = "An explicit scope is required; empty scope grants nothing")
            List<String> scope,

            String rights,

            @jakarta.validation.constraints.NotNull(message = "expiresAt is required")
            @jakarta.validation.constraints.Future(message = "expiresAt must be in the future")
            Instant expiresAt
    ) {}
}
