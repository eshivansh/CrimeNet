package com.crimenet.documents;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.infrastructure.MinioStorageService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

/**
 * Corrupts a stored object so that integrity verification can be seen to fail.
 *
 * <p><b>Demonstration tooling. Never part of a production build.</b> The {@code dev}
 * profile guard is the control that keeps it out: without {@code spring.profiles.active=dev}
 * this bean is not created and the endpoint does not exist.
 *
 * <p>Why it is worth having. {@link DocumentService#verifyIntegrity} re-downloads the
 * stored object, recomputes its SHA-256 and compares it with the digest recorded at upload.
 * In normal operation that comparison always succeeds, so its failure branch — which
 * records an {@code INTEGRITY_FAILURE} audit event — had never once executed. A check only
 * ever seen to pass demonstrates nothing; a reviewer cannot tell it from a hard-coded tick.
 *
 * <p>This service edits the bytes in object storage and leaves the database untouched,
 * which is exactly the shape of the threat being defended against: someone with access to
 * the storage layer, going around the application. The recorded hash still describes the
 * original file, so the very next verification detects the mismatch.
 *
 * <p>The tampering itself is audited. Real tampering would leave no such trace, but a
 * simulation that hid itself would be dishonest — the entry makes clear the corruption was
 * deliberate, and it sits in the trail alongside the INTEGRITY_FAILURE that follows it.
 */
@Slf4j
@Service
@Profile("dev")
@RequiredArgsConstructor
public class TamperSimulationService {

    private final DocumentRepository documentRepository;
    private final DocumentVersionRepository documentVersionRepository;
    private final MinioStorageService storageService;
    private final PolicyEvaluationService policyService;
    private final UserService userService;
    private final AuditService auditService;

    /** Bytes overwritten at the start of the object. Enough to change the digest; small enough to stay a valid file of its type. */
    private static final int BYTES_TO_CORRUPT = 8;

    private static final SecureRandom RANDOM = new SecureRandom();

    @Transactional
    public TamperResult tamperWith(UUID documentId) {
        Document doc = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found: " + documentId));

        // Even a dev tool should not let someone touch a case they have no access to.
        policyService.enforcePermission("DOCUMENT", "READ");
        policyService.enforceCaseAccess(doc.getCaseId());

        if (doc.getCurrentVersionId() == null) {
            throw new IllegalStateException("Document has no committed version to tamper with");
        }
        DocumentVersion version = documentVersionRepository.findById(doc.getCurrentVersionId())
                .orElseThrow(() -> new EntityNotFoundException("Version not found"));

        byte[] original = storageService.downloadDocument(version.getObjectKey());
        if (original.length == 0) {
            throw new IllegalStateException("Stored object is empty; nothing to corrupt");
        }

        // Overwrite with fresh random bytes rather than flipping bits. XOR would be an
        // involution: tampering the same object twice would restore it byte for byte, so a
        // second press of the button would silently "repair" the file and the next
        // verification would pass — the opposite of the point being demonstrated.
        byte[] corrupted = original.clone();
        int changed = Math.min(BYTES_TO_CORRUPT, corrupted.length);
        byte[] noise = new byte[changed];
        do {
            RANDOM.nextBytes(noise);
        } while (Arrays.equals(noise, Arrays.copyOf(original, changed)));
        System.arraycopy(noise, 0, corrupted, 0, changed);

        storageService.uploadDocument(version.getObjectKey(), corrupted, version.getMimeType());

        AppUser currentUser = userService.getCurrentUser();
        auditService.record("TAMPER_SIMULATION_EXECUTED", currentUser.getId(), documentId, doc.getCaseId(),
                Map.of("objectKey", version.getObjectKey(),
                        "bytesChanged", changed,
                        "note", "Demonstration only - stored object modified behind the application"));

        log.warn("TAMPER SIMULATION: {} byte(s) of object {} corrupted by user {}. "
                        + "The database still holds the original hash; the next integrity check will fail.",
                changed, version.getObjectKey(), currentUser.getId());

        return new TamperResult(
                documentId,
                version.getVersionNo(),
                changed,
                version.getContentHash(),
                "Stored object modified directly in object storage. The database still holds the "
                        + "original digest — run Verify integrity to see the mismatch detected.");
    }

    public record TamperResult(
            UUID documentId,
            int versionNo,
            int bytesChanged,
            String unchangedStoredHash,
            String nextStep
    ) {}
}
