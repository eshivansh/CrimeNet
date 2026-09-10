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

        // Check for deduplication (§20)
        java.util.Optional<DocumentVersion> existingVersion = documentVersionRepository.findByContentHash(contentHash).stream().findFirst();
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
            // Upload to Quarantine (outside DB transaction boundary)
            try {
                storageService.uploadToQuarantine(quarantineKey, content, contentType);
            } catch (Exception e) {
                log.error("MinIO quarantine upload failed for document {}: {}", doc.getId(), e.getMessage());
                version.setUploadStatus("FAILED");
                documentVersionRepository.save(version);
                throw new RuntimeException("File upload failed", e);
            }

            // Malware Scan
            if (!malwareScannerService.isClean(content, originalFilename)) {
                storageService.deleteFromQuarantine(quarantineKey);
                version.setUploadStatus("FAILED_MALWARE");
                documentVersionRepository.save(version);
                auditService.record("MALWARE_DETECTED", currentUser.getId(), doc.getId(), caseId,
                        Map.of("filename", originalFilename != null ? originalFilename : "unknown", "mimeType", contentType));
                throw new RuntimeException("Upload rejected: Malware detected");
            }

            // Move to Documents Bucket
            try {
                storageService.moveToDocuments(quarantineKey, objectKey);
                storageService.deleteFromQuarantine(quarantineKey);
                version.setUploadStatus("COMMITTED");
            } catch (Exception e) {
                log.error("MinIO move to documents failed for document {}: {}", doc.getId(), e.getMessage());
                version.setUploadStatus("FAILED");
                documentVersionRepository.save(version);
                throw new RuntimeException("File processing failed", e);
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
                "objectKey", objectKey
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
        } catch (Exception e) {
            log.error("Integrity check failed for document {}: {}", documentId, e.getMessage());
            return new IntegrityCheckResult(documentId, currentVersion.getVersionNo(),
                    currentVersion.getContentHash(), null, false);
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

        return storageService.generatePresignedUrl("crimenet-documents", version.getObjectKey(), 300);
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

    private String generateBusinessId() {
        long count = documentRepository.count() + 1;
        return String.format("DOC-UP-%s-%06d", Year.now().getValue(), count);
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
