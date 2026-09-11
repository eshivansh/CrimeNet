package com.crimenet.evidence;

import com.crimenet.audit.AuditService;
import com.crimenet.documents.HashService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.documents.MalwareScannerService;
import com.crimenet.infrastructure.MinioStorageService;
import com.crimenet.policy.PolicyEvaluationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class EvidenceService {

    private final EvidenceRepository evidenceRepository;
    private final CustodyEventRepository custodyEventRepository;
    private final EvidenceArtifactRepository evidenceArtifactRepository;
    private final HashService hashService;
    private final MinioStorageService storageService;
    private final MalwareScannerService malwareScannerService;
    private final UserService userService;
    private final PolicyEvaluationService policyService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final com.crimenet.common.IdentifierSequenceService identifierSequenceService;
    private final CustodyChainService custodyChainService;

    @Value("${crimenet.documents.max-size-bytes:52428800}")
    private long maxSizeBytes;

    @Value("${crimenet.documents.allowed-mime-types}")
    private List<String> allowedMimeTypes;

    /**
     * Register new evidence and create the initial REGISTERED custody event.
     */
    @Transactional
    public Evidence registerEvidence(RegisterEvidenceRequest request) {
        // Both are stored NOT NULL and initialHash is also read back into the audit payload
        // via Map.of(), which rejects nulls. Without these checks a caller that omits either
        // field gets an opaque 500 NullPointerException instead of a 400 naming the problem.
        if (request.caseId() == null) {
            throw new IllegalArgumentException("caseId is required");
        }
        if (request.initialHash() == null || request.initialHash().isBlank()) {
            throw new IllegalArgumentException(
                    "initialHash is required: supply the SHA-256 digest recorded when the evidence was collected");
        }

        policyService.enforceCasePermission(request.caseId(), "EVIDENCE", "CREATE");

        AppUser currentUser = userService.getCurrentUser();
        String evidenceCode = generateEvidenceCode();

        Evidence evidence = Evidence.builder()
                .caseId(request.caseId())
                .orgId(currentUser.getOrgId())
                .evidenceCode(evidenceCode)
                .title(request.title())
                .description(request.description())
                .source(request.source())
                .sourceDevice(request.sourceDevice())
                .collectedBy(currentUser.getId())
                .collectedAt(request.collectedAt() != null ? request.collectedAt() : Instant.now())
                .location(request.location())
                .initialHash(request.initialHash())
                .classification(request.classification() != null ? request.classification() : "STANDARD")
                .build();

        evidence = evidenceRepository.save(evidence);

        // Create initial custody event: REGISTERED. Hashed over every field, like every
        // later link, so the origin of the chain is protected the same way.
        CustodyEvent initialEvent = CustodyEvent.builder()
                .evidenceId(evidence.getId())
                .toActor(currentUser.getId())
                .action("REGISTERED")
                .purpose("Initial evidence registration")
                .location(request.location())
                .build();
        initialEvent.setCreatedAt(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS));
        initialEvent.setEventHash(custodyChainService.computeEventHash(initialEvent, null));

        custodyEventRepository.save(initialEvent);

        auditService.record("EVIDENCE_REGISTERED", currentUser.getId(), evidence.getId(), request.caseId(),
                Map.of("evidenceCode", evidenceCode, "initialHash", request.initialHash()));

        log.info("Evidence registered: {} for case {}", evidenceCode, request.caseId());
        return evidence;
    }

    /**
     * Transfer custody with optimistic locking on previous_event_id.
     * Rejects if the provided previousEventId doesn't match the current head.
     */
    @Transactional
    public CustodyEvent transferCustody(UUID evidenceId, TransferCustodyRequest request) {
        // Acquire row-level lock (SELECT ... FOR UPDATE) to eliminate TOCTOU race conditions
        Evidence evidence = evidenceRepository.findByIdForUpdate(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));

        policyService.enforceCaseAccess(evidence.getCaseId());

        AppUser currentUser = userService.getCurrentUser();

        // Optimistic lock: verify previous_event_id matches current head
        CustodyEvent currentHead = custodyEventRepository.findTopByEvidenceIdOrderByCreatedAtDesc(evidenceId)
                .orElseThrow(() -> new IllegalStateException("No custody events found for evidence: " + evidenceId));

        // Custodian ownership check: only the active custodian holding the item may transfer it
        if (currentHead.getToActor() != null && !currentUser.getId().equals(currentHead.getToActor()) && !policyService.hasRole("ADMIN")) {
            log.warn("CUSTODY_TRANSFER_DENIED: User {} attempted transfer of evidence {} currently held by {}",
                    currentUser.getId(), evidenceId, currentHead.getToActor());
            throw new org.springframework.security.access.AccessDeniedException(
                    "Custody transfer rejected: Only the current recorded custodian can transfer this evidence.");
        }

        // Mandatory optimistic lock: previousEventId MUST be supplied and must match current head
        if (request.previousEventId() == null || !currentHead.getId().equals(request.previousEventId())) {
            log.warn("Stale or unversioned custody transfer rejected for evidence {}: expected head {}, got {}",
                    evidenceId, currentHead.getId(), request.previousEventId());
            throw new IllegalStateException("Custody transfer rejected: previousEventId is mandatory and must match current chain head (" +
                    currentHead.getId() + ")");
        }

        if (currentUser.getId().equals(request.toActorId())) {
            throw new IllegalArgumentException("Cannot transfer custody to yourself");
        }

        // Verify target recipient exists and belongs to same organization
        AppUser recipient = userService.getUser(request.toActorId());
        if (!recipient.getOrgId().equals(evidence.getOrgId()) && !policyService.hasRole("ADMIN")) {
            throw new SecurityException("Cross-tenant custody transfer denied: Recipient officer belongs to a different organization");
        }

        // Build the hash-linked event.
        //
        // The hash used to cover action, evidenceId, fromActor, toActor and previousEventId
        // only — leaving purpose, location, notes, signature and the timestamp persisted but
        // unauthenticated. The recorded location of a seizure could be rewritten and the
        // chain still validated perfectly, which is exactly the claim a §65B certificate
        // rests on. Every persisted field is now covered.
        Instant occurredAt = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        CustodyEvent event = CustodyEvent.builder()
                .evidenceId(evidenceId)
                .fromActor(currentUser.getId())
                .toActor(request.toActorId())
                .action(request.action())
                .purpose(request.purpose())
                .location(request.location())
                .notes(request.notes())
                .previousEventId(currentHead.getId())
                .previousEventHash(currentHead.getEventHash())
                .signature(request.signature())
                .build();
        event.setCreatedAt(occurredAt);
        event.setEventHash(custodyChainService.computeEventHash(event, currentHead.getEventHash()));
        String eventHash = event.getEventHash();

        event = custodyEventRepository.save(event);

        auditService.record("CUSTODY_TRANSFERRED", currentUser.getId(), evidenceId, evidence.getCaseId(),
                Map.of("action", request.action(), "fromActor", currentUser.getId().toString(),
                        "toActor", request.toActorId().toString(), "eventHash", eventHash));

        log.info("Custody transferred for evidence {}: {} → {} ({})",
                evidenceId, currentUser.getId(), request.toActorId(), request.action());
        return event;
    }

    /**
     * Get the full custody chain for an evidence item.
     */
    public List<CustodyEvent> getCustodyChain(UUID evidenceId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));
        policyService.enforceCaseAccess(evidence.getCaseId());
        return custodyChainService.orderedChain(evidenceId);
    }

    /**
     * Recompute and walk the custody chain for an evidence item.
     *
     * <p>The chain was tamper-evident in structure and nothing ever read that evidence:
     * no code path recomputed an event hash or checked the linkage, so a break was
     * invisible through every API.
     */
    public CustodyChainService.CustodyChainVerification verifyCustodyChain(UUID evidenceId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));
        policyService.enforceCaseAccess(evidence.getCaseId());
        return custodyChainService.verify(evidenceId);
    }

    /**
     * Get evidence by ID.
     */
    public Evidence getEvidence(UUID evidenceId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));
        policyService.enforceCaseAccess(evidence.getCaseId());
        return evidence;
    }

    /**
     * List evidence for a case.
     */
    public List<Evidence> listEvidenceForCase(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return evidenceRepository.findByCaseId(caseId);
    }

    /**
     * Add a digital artifact (e.g. photo, report) to an evidence record.
     */
    @Transactional
    public EvidenceArtifact addArtifact(UUID evidenceId, String artifactType, String description, MultipartFile file) throws IOException {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));

        policyService.enforceCasePermission(evidence.getCaseId(), "EVIDENCE", "CREATE");

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
        String objectKey = String.format("%s/%s/%s/%s.enc",
                currentUser.getOrgId(), evidence.getCaseId(), evidence.getId(), contentHash);
        String quarantineKey = "quarantine-evidence/" + objectKey;

        // Upload to Quarantine
        storageService.uploadToQuarantine(quarantineKey, content, contentType);

        // Malware Scan
        if (!malwareScannerService.isClean(content, originalFilename)) {
            storageService.deleteFromQuarantine(quarantineKey);
            auditService.record("MALWARE_DETECTED_IN_EVIDENCE", currentUser.getId(), evidenceId, evidence.getCaseId(),
                    Map.of("filename", originalFilename != null ? originalFilename : "unknown", "mimeType", contentType));
            throw new RuntimeException("Upload rejected: Malware detected");
        }

        // Move to Evidence Bucket
        try {
            storageService.moveToEvidence(quarantineKey, objectKey);
            storageService.deleteFromQuarantine(quarantineKey);
        } catch (Exception e) {
            log.error("MinIO move to evidence failed for {}: {}", evidenceId, e.getMessage());
            throw new RuntimeException("File processing failed", e);
        }

        EvidenceArtifact artifact = EvidenceArtifact.builder()
                .evidenceId(evidenceId)
                .artifactType(artifactType)
                .objectKey(objectKey)
                .contentHash(contentHash)
                .sizeBytes(content.length)
                .mimeType(contentType)
                .description(description)
                .createdBy(currentUser.getId())
                .build();

        artifact = evidenceArtifactRepository.save(artifact);

        auditService.record("EVIDENCE_ARTIFACT_ADDED", currentUser.getId(), evidenceId, evidence.getCaseId(),
                Map.of("artifactId", artifact.getId().toString(), "artifactType", artifactType, "contentHash", contentHash));

        log.info("Evidence artifact added to evidence {}: type={}, hash={}", evidenceId, artifactType, contentHash);
        return artifact;
    }

    /**
     * List artifacts for an evidence record.
     */
    public List<EvidenceArtifact> listArtifacts(UUID evidenceId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));
        policyService.enforceCaseAccess(evidence.getCaseId());
        return evidenceArtifactRepository.findByEvidenceId(evidenceId);
    }

    /**
     * Generate secure presigned download URL for an evidence artifact.
     */
    public String getArtifactDownloadUrl(UUID evidenceId, UUID artifactId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));
        policyService.enforceCaseAccess(evidence.getCaseId());

        EvidenceArtifact artifact = evidenceArtifactRepository.findById(artifactId)
                .orElseThrow(() -> new EntityNotFoundException("Artifact not found: " + artifactId));

        if (!artifact.getEvidenceId().equals(evidenceId)) {
            throw new IllegalArgumentException("Artifact does not belong to the specified evidence");
        }

        AppUser currentUser = userService.getCurrentUser();
        auditService.record("EVIDENCE_ARTIFACT_DOWNLOADED", currentUser.getId(), artifactId, evidence.getCaseId(),
                Map.of("evidenceId", evidenceId.toString(), "contentHash", artifact.getContentHash()));

        return storageService.generatePresignedUrl("crimenet-evidence", artifact.getObjectKey(), 300);
    }

    private String generateEvidenceCode() {
        long serial = identifierSequenceService.next("evidence_code_seq");
        return String.format("E-%06d", serial);
    }

    private String canonicalPayload(Map<String, String> data) {
        try {
            return objectMapper.writeValueAsString(new java.util.TreeMap<>(data));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize payload", e);
        }
    }

    // Request DTOs
    public record RegisterEvidenceRequest(
            UUID caseId,
            String title,
            String description,
            String source,
            String sourceDevice,
            Instant collectedAt,
            String location,
            String initialHash,
            String classification
    ) {}

    public record TransferCustodyRequest(
            UUID toActorId,
            String action,
            String purpose,
            String location,
            String notes,
            UUID previousEventId,
            String signature
    ) {}
}
