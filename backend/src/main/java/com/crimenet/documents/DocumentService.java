package com.crimenet.documents;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.infrastructure.MinioStorageService;
import com.crimenet.infrastructure.RabbitMqPublisher;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.time.Year;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DocumentService {

    private final DocumentRepository documentRepository;
    private final DocumentVersionRepository documentVersionRepository;
    private final HashService hashService;
    private final MinioStorageService storageService;
    private final UserService userService;
    private final PolicyEvaluationService policyService;
    private final AuditService auditService;
    private final MalwareScannerService malwareScannerService;
    private final RabbitMqPublisher rabbitMqPublisher;
    private final com.crimenet.common.IdentifierSequenceService identifierSequenceService;
    private final UploadFailureRecorder uploadFailureRecorder;

    @Value("${crimenet.documents.max-size-bytes:52428800}")
    private long maxSizeBytes;

    @Value("${crimenet.documents.allowed-mime-types}")
    private List<String> allowedMimeTypes;

    private final com.crimenet.infrastructure.IdempotencyRecordRepository idempotencyRecordRepository;

    /**
     * Create a new document with its first version (file upload).
     * Implements the outbox pattern from §4.3:
     *   1. Compute hash from raw bytes
     *   2. Insert PENDING version row
     *   3. Upload to MinIO
     *   4. Mark COMMITTED + update document.current_version_id + audit event (atomic)
     */
    @Transactional
    public Document createDocument(UUID caseId, String docType, String title,
                                   String classification, MultipartFile file, String idempotencyKey) throws IOException {
        policyService.enforceCasePermission(caseId, "DOCUMENT", "CREATE");

        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            java.util.Optional<com.crimenet.infrastructure.IdempotencyRecord> existing = idempotencyRecordRepository.findById(idempotencyKey);
            if (existing.isPresent()) {
                log.info("Idempotent request matched key: {}. Returning existing resource {}", idempotencyKey, existing.get().getResourceId());
                return getDocument(UUID.fromString(existing.get().getResourceId()));
            }
        }

        AppUser currentUser = userService.getCurrentUser();
        byte[] content = file.getBytes();
        String contentType = file.getContentType() != null ? file.getContentType() : "application/octet-stream";
        String originalFilename = file.getOriginalFilename();
        String safeFilename = sanitizeFilename(originalFilename);

        // 1. Validate MIME and Size
        if (content.length > maxSizeBytes) {
            throw new IllegalArgumentException("File size exceeds maximum allowed size");
        }
        if (allowedMimeTypes != null && !allowedMimeTypes.contains(contentType)) {
            throw new IllegalArgumentException("File type not allowed: " + contentType);
        }

        String contentHash = hashService.computeSha256(content);
        String businessId = generateBusinessId();

        // Create document record
        Document doc = Document.builder()
                .caseId(caseId)
                .orgId(currentUser.getOrgId())
                .businessId(businessId)
                .docType(docType)
                .title((title != null && !title.isBlank()) ? title.trim() : safeFilename)
                .classification(classification != null ? classification : "STANDARD")
                .createdBy(currentUser.getId())
                .build();
        doc = documentRepository.save(doc);

        // Create version (PENDING)
        String objectKey = buildObjectKey(currentUser.getOrgId(), caseId, doc.getId(), 1, contentHash);
        String quarantineKey = "quarantine/" + objectKey;

        // Deduplication (§20), scoped to this organization and to versions that committed.
        //
        // The lookup used to be global and unfiltered, with three consequences. A document
        // in one organization pointed at another organization's object key, so a retention
        // purge on their case destroyed this one's bytes, and the presigned URL disclosed a
        // path carrying the other tenant's org, case and document ids. And because a
        // rejected upload leaves a row carrying its content hash, re-uploading the identical
        // bytes under a different filename matched that row and jumped straight to
        // COMMITTED, skipping quarantine and the malware scan entirely.
        java.util.Optional<DocumentVersion> existingVersion =
                findReusableVersion(contentHash, currentUser.getOrgId());
        boolean isDuplicate = existingVersion.isPresent();

        DocumentVersion version = DocumentVersion.builder()
                .documentId(doc.getId())
                .versionNo(1)
                .contentHash(contentHash)
                .objectKey(isDuplicate ? existingVersion.get().getObjectKey() : objectKey)
                .sizeBytes(content.length)
                .mimeType(contentType)
                .uploadStatus(isDuplicate ? "COMMITTED" : "PENDING")
                .createdBy(currentUser.getId())
                .build();

        version = documentVersionRepository.save(version);

        if (!isDuplicate) {
            // On failure handling below: setting a status, saving, then throwing inside the
            // same transaction rolled that row back along with everything else, so the
            // documented FAILED / FAILED_MALWARE outbox states never persisted and a
            // rejected malware upload left no trace for forensic review. Terminal failures
            // are now recorded in their own transaction.
            try {
                storageService.uploadToQuarantine(quarantineKey, content, contentType);
            } catch (Exception e) {
                log.error("MinIO quarantine upload failed for document {}: {}", doc.getId(), e.getMessage());
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED",
                        "Quarantine upload failed: " + e.getMessage());
                throw new StorageUnavailableException("File upload failed", e);
            }

            // isClean now reads the content; a file that cannot be scanned raises
            // MalwareScanUnavailableException rather than being treated as clean.
            if (!malwareScannerService.isClean(content, originalFilename)) {
                storageService.deleteFromQuarantine(quarantineKey);
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED_MALWARE",
                        "Malware detected in " + (originalFilename != null ? originalFilename : "unknown"));
                auditService.record("MALWARE_DETECTED", currentUser.getId(), doc.getId(), caseId,
                        Map.of("filename", originalFilename != null ? originalFilename : "unknown", "mimeType", contentType));
                throw new MalwareDetectedException("Upload rejected: the file did not pass malware scanning.");
            }

            // Move to Documents Bucket
            try {
                storageService.moveToDocuments(quarantineKey, objectKey);
                storageService.deleteFromQuarantine(quarantineKey);
                version.setUploadStatus("COMMITTED");
            } catch (Exception e) {
                log.error("MinIO move to documents failed for document {}: {}", doc.getId(), e.getMessage());
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED",
                        "Move out of quarantine failed: " + e.getMessage());
                throw new StorageUnavailableException("File processing failed", e);
            }
        } else {
            // Duplicate content: reuse existing verified object without hitting quarantine
            version.setUploadStatus("COMMITTED");
            log.info("Document {} version 1 reuses existing content hash: {}", businessId, contentHash);
        }

        documentVersionRepository.save(version);

        // Update document to point to current version
        doc.setCurrentVersionId(version.getId());
        doc.setUpdatedAt(Instant.now());
        documentRepository.save(doc);

        // Audit
        Map<String, Object> auditPayload = Map.of(
                "documentId", doc.getId().toString(),
                "caseId", caseId.toString(),
                "businessId", businessId, 
                "versionNo", 1, 
                "contentHash", contentHash,
                "sizeBytes", content.length, 
                "mimeType", contentType,
                // The key the row actually points at. On a deduplicated upload this differs
                // from the computed objectKey, so the audit trail used to record a location
                // the bytes were never stored at - and the OCR worker, which downloads
                // payload.objectKey, requested a nonexistent object and redelivered forever.
                "objectKey", version.getObjectKey(),
                "deduplicated", isDuplicate
        );
        auditService.record("DOCUMENT_VERSION_CREATED", currentUser.getId(), doc.getId(), caseId, auditPayload);

        // Publish event to RabbitMQ
        rabbitMqPublisher.publishDocumentVersionCreated(auditPayload);

        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            com.crimenet.infrastructure.IdempotencyRecord record = com.crimenet.infrastructure.IdempotencyRecord.builder()
                    .idempotencyKey(idempotencyKey)
                    .resourceId(doc.getId().toString())
                    .statusCode(201)
                    .build();
            idempotencyRecordRepository.save(record);
        }

        log.info("Document created: {} (version 1, hash: {})", businessId, contentHash);
        return doc;
    }

    /**
     * Upload a new revision/version to an existing document.
     * Preserves all previous versions immutably and increments version_no.
     */
    @Transactional
    public DocumentVersion addDocumentVersion(UUID documentId, MultipartFile file) throws IOException {
        Document doc = getDocument(documentId);
        policyService.enforceCasePermission(doc.getCaseId(), "DOCUMENT", "UPDATE");

        AppUser currentUser = userService.getCurrentUser();
        byte[] content = file.getBytes();
        String contentType = file.getContentType() != null ? file.getContentType() : "application/octet-stream";
        String originalFilename = file.getOriginalFilename();

        if (content.length > maxSizeBytes) {
            throw new IllegalArgumentException("File size exceeds maximum allowed size");
        }
        if (allowedMimeTypes != null && !allowedMimeTypes.contains(contentType)) {
            throw new IllegalArgumentException("File type not allowed: " + contentType);
        }

        String contentHash = hashService.computeSha256(content);

        // Find current highest version number
        int nextVersionNo = documentVersionRepository.findTopByDocumentIdOrderByVersionNoDesc(doc.getId())
                .map(v -> v.getVersionNo() + 1)
                .orElse(1);

        String objectKey = buildObjectKey(currentUser.getOrgId(), doc.getCaseId(), doc.getId(), nextVersionNo, contentHash);
        String quarantineKey = "quarantine/" + objectKey;

        // Check deduplication
        java.util.Optional<DocumentVersion> existingVersion =
                findReusableVersion(contentHash, doc.getOrgId());
        boolean isDuplicate = existingVersion.isPresent();

        DocumentVersion version = DocumentVersion.builder()
                .documentId(doc.getId())
                .versionNo(nextVersionNo)
                .contentHash(contentHash)
                .objectKey(isDuplicate ? existingVersion.get().getObjectKey() : objectKey)
                .sizeBytes(content.length)
                .mimeType(contentType)
                .uploadStatus(isDuplicate ? "COMMITTED" : "PENDING")
                .createdBy(currentUser.getId())
                .build();

        version = documentVersionRepository.save(version);

        if (!isDuplicate) {
            try {
                storageService.uploadToQuarantine(quarantineKey, content, contentType);
            } catch (Exception e) {
                log.error("MinIO quarantine upload failed for document {} version {}: {}", doc.getId(), nextVersionNo, e.getMessage());
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED", e.getMessage());
                throw new StorageUnavailableException("File upload failed", e);
            }

            if (!malwareScannerService.isClean(content, originalFilename)) {
                storageService.deleteFromQuarantine(quarantineKey);
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED_MALWARE",
                        "Malware detected in " + (originalFilename != null ? originalFilename : "unknown"));
                auditService.record("MALWARE_DETECTED", currentUser.getId(), doc.getId(), doc.getCaseId(),
                        Map.of("filename", originalFilename != null ? originalFilename : "unknown", "mimeType", contentType, "versionNo", nextVersionNo));
                throw new MalwareDetectedException("Upload rejected: the file did not pass malware scanning.");
            }

            try {
                storageService.moveToDocuments(quarantineKey, objectKey);
                storageService.deleteFromQuarantine(quarantineKey);
                version.setUploadStatus("COMMITTED");
            } catch (Exception e) {
                log.error("MinIO move to documents failed for document {} version {}: {}", doc.getId(), nextVersionNo, e.getMessage());
                uploadFailureRecorder.recordFailure(version.getId(), "FAILED", e.getMessage());
                throw new StorageUnavailableException("File processing failed", e);
            }
        } else {
            version.setUploadStatus("COMMITTED");
            log.info("Document {} version {} reuses existing content hash: {}", doc.getBusinessId(), nextVersionNo, contentHash);
        }

        version = documentVersionRepository.save(version);

        // Update document current_version_id
        doc.setCurrentVersionId(version.getId());
        doc.setUpdatedAt(Instant.now());
        documentRepository.save(doc);

        // Audit
        Map<String, Object> auditPayload = Map.of(
                "documentId", doc.getId().toString(),
                "caseId", doc.getCaseId().toString(),
                "businessId", doc.getBusinessId(),
                "versionNo", nextVersionNo,
                "contentHash", contentHash,
                "sizeBytes", content.length,
                "mimeType", contentType,
                // The key the row actually points at. On a deduplicated upload this differs
                // from the computed objectKey, so the audit trail used to record a location
                // the bytes were never stored at - and the OCR worker, which downloads
                // payload.objectKey, requested a nonexistent object and redelivered forever.
                "objectKey", version.getObjectKey(),
                "deduplicated", isDuplicate
        );
        auditService.record("DOCUMENT_VERSION_CREATED", currentUser.getId(), doc.getId(), doc.getCaseId(), auditPayload);
        rabbitMqPublisher.publishDocumentVersionCreated(auditPayload);

        log.info("Document {} new version {} created (hash: {})", doc.getBusinessId(), nextVersionNo, contentHash);
        return version;
    }

    /**
     * Get document by ID with case access check.
     */
    public Document getDocument(UUID documentId) {
        Document doc = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found: " + documentId));
        policyService.enforceCaseAccess(doc.getCaseId());
        return doc;
    }

    /**
     * List all versions of a document (immutable list).
     */
    public List<DocumentVersion> getVersions(UUID documentId) {
        Document doc = getDocument(documentId);
        return documentVersionRepository.findByDocumentIdOrderByVersionNoAsc(doc.getId());
    }

    /**
     * List documents for a case.
     */
    public List<Document> listDocumentsForCase(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return documentRepository.findByCaseId(caseId);
    }

    /**
     * Verify document integrity: recompute hash and compare.
     */
    public IntegrityCheckResult verifyIntegrity(UUID documentId) {
        Document doc = getDocument(documentId);
        DocumentVersion currentVersion = documentVersionRepository.findById(doc.getCurrentVersionId())
                .orElseThrow(() -> new EntityNotFoundException("Version not found"));

        try {
            byte[] storedContent = storageService.downloadDocument(currentVersion.getObjectKey());
            String recomputedHash = hashService.computeSha256(storedContent);
            boolean matches = recomputedHash.equals(currentVersion.getContentHash());

            AppUser currentUser = userService.getCurrentUser();
            auditService.record(
                    matches ? "INTEGRITY_CHECK_PASSED" : "INTEGRITY_FAILURE",
                    currentUser.getId(), documentId, doc.getCaseId(),
                    Map.of("storedHash", currentVersion.getContentHash(),
                            "recomputedHash", recomputedHash, "matches", matches));

            if (!matches) {
                log.error("INTEGRITY_FAILURE: Document {} version {} hash mismatch! Stored={}, Recomputed={}",
                        documentId, currentVersion.getVersionNo(), currentVersion.getContentHash(), recomputedHash);
            }

            return new IntegrityCheckResult(documentId, currentVersion.getVersionNo(),
                    currentVersion.getContentHash(), recomputedHash, matches);
        } catch (StorageUnavailableException e) {
            throw e;
        } catch (Exception e) {
            // A storage outage is not tamper evidence. This used to return valid=false with
            // a null recomputed hash — byte-for-byte the same result as a genuine mismatch —
            // so a MinIO restart made every document in the system look tampered, and unlike
            // the mismatch branch it recorded no audit event either.
            log.error("Integrity check could not complete for document {}: {}", documentId, e.getMessage());
            throw new StorageUnavailableException(
                    "Integrity verification is unavailable: the stored object could not be read. "
                            + "This is not an integrity failure.", e);
        }
    }

    /**
     * Generate secure presigned download URL for a document version with access check and audit logging.
     */
    public String getDocumentDownloadUrl(UUID documentId, UUID versionId) {
        Document doc = getDocument(documentId);
        policyService.enforceCaseAccess(doc.getCaseId());

        UUID targetVersionId = versionId != null ? versionId : doc.getCurrentVersionId();
        DocumentVersion version = documentVersionRepository.findById(targetVersionId)
                .orElseThrow(() -> new EntityNotFoundException("Document version not found: " + targetVersionId));

        if (!version.getDocumentId().equals(documentId)) {
            throw new IllegalArgumentException("Version does not belong to the specified document");
        }

        AppUser currentUser = userService.getCurrentUser();
        auditService.record("DOCUMENT_DOWNLOADED", currentUser.getId(), targetVersionId, doc.getCaseId(),
                Map.of("documentId", documentId.toString(), "contentHash", version.getContentHash()));

        return storageService.generatePresignedUrl(
                "crimenet-documents", version.getObjectKey(), 300, doc.getTitle());
    }

    private String sanitizeFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            return "document.bin";
        }
        // Strip path traversal attempts and keep only filename
        String clean = filename.replace("\\", "/");
        int lastSlash = clean.lastIndexOf('/');
        if (lastSlash >= 0) {
            clean = clean.substring(lastSlash + 1);
        }
        clean = clean.replaceAll("[^a-zA-Z0-9._\\-]", "_");
        return clean.isBlank() ? "document.bin" : clean;
    }

    /**
     * A committed version in the same organization whose stored object may be reused.
     *
     * <p>Both filters matter. Without the status filter, a row left behind by a rejected
     * upload becomes a dedup target and lets the next upload of those bytes skip scanning.
     * Without the organization filter, two tenants share one physical object and either
     * one's retention purge destroys the other's evidence.
     */
    private java.util.Optional<DocumentVersion> findReusableVersion(String contentHash, UUID orgId) {
        if (orgId == null) {
            return java.util.Optional.empty();
        }
        return documentVersionRepository.findByContentHash(contentHash).stream()
                .filter(v -> "COMMITTED".equals(v.getUploadStatus()))
                .filter(v -> documentRepository.findById(v.getDocumentId())
                        .map(d -> orgId.equals(d.getOrgId()))
                        .orElse(false))
                .findFirst();
    }

    private String generateBusinessId() {
        long serial = identifierSequenceService.next("document_business_seq");
        return String.format("DOC-UP-%s-%06d", Year.now().getValue(), serial);
    }

    private String buildObjectKey(UUID orgId, UUID caseId, UUID docId, int versionNo, String hash) {
        return String.format("%s/%s/%s/%d/%s.enc", orgId, caseId, docId, versionNo, hash);
    }

    public record IntegrityCheckResult(
            UUID documentId,
            int versionNo,
            String storedHash,
            String recomputedHash,
            boolean valid
    ) {}
}
