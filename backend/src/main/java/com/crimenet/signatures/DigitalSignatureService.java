package com.crimenet.signatures;

import com.crimenet.audit.AuditService;
import com.crimenet.documents.Document;
import com.crimenet.documents.DocumentRepository;
import com.crimenet.documents.DocumentVersion;
import com.crimenet.documents.DocumentVersionRepository;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class DigitalSignatureService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final DocumentRepository documentRepository;
    private final DocumentVersionRepository documentVersionRepository;
    private final DocumentSignatureRepository signatureRepository;
    private final PolicyEvaluationService policyService;
    private final UserService userService;
    private final AuditService auditService;

    // Per-officer identity keystore: binds each discrete officer identity to their own private/public keypair
    // when signing in-session without an external hardware PKCS#11/eMudhra token.
    private final java.util.concurrent.ConcurrentMap<UUID, KeyPair> officerKeyStore = new java.util.concurrent.ConcurrentHashMap<>();

    private KeyPair getOrCreateOfficerKeyPair(UUID officerId) {
        return officerKeyStore.computeIfAbsent(officerId, id -> {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(2048);
                return kpg.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate cryptographic keypair for officer " + id, e);
            }
        });
    }

    @Transactional
    public DocumentSignature signDocument(UUID documentId, UUID versionId, String signatureBase64,
                                         String publicKeyPem, String algorithm) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found: " + documentId));

        policyService.enforceCasePermission(document.getCaseId(), "DOCUMENT", "SIGN");

        UUID targetVersionId = versionId != null ? versionId : document.getCurrentVersionId();
        DocumentVersion version = documentVersionRepository.findById(targetVersionId)
                .orElseThrow(() -> new EntityNotFoundException("Document version not found: " + targetVersionId));

        AppUser currentUser = userService.getCurrentUser();
        String docHash = version.getContentHash();
        String sigAlgo = (algorithm != null && !algorithm.isBlank()) ? algorithm : "SHA256withRSA";

        String finalSignature = signatureBase64;
        String finalPublicKey = publicKeyPem;
        boolean isValid = false;

        if (finalSignature != null && !finalSignature.isBlank() && finalPublicKey != null && !finalPublicKey.isBlank()) {
            isValid = verifyCryptographicSignature(docHash, finalSignature, finalPublicKey, sigAlgo);
        } else {
            // Generate valid cryptographic signature using officer identity session key
            try {
                KeyPair officerKeyPair = getOrCreateOfficerKeyPair(currentUser.getId());
                Signature sig = Signature.getInstance(sigAlgo, BouncyCastleProvider.PROVIDER_NAME);
                sig.initSign(officerKeyPair.getPrivate());
                sig.update(docHash.getBytes(StandardCharsets.UTF_8));
                byte[] signatureBytes = sig.sign();
                finalSignature = Base64.getEncoder().encodeToString(signatureBytes);
                finalPublicKey = Base64.getEncoder().encodeToString(officerKeyPair.getPublic().getEncoded());
                isValid = true;
            } catch (Exception e) {
                log.error("Failed to generate digital signature for officer {}: {}", currentUser.getId(), e.getMessage());
                throw new RuntimeException("Digital signature generation failed", e);
            }
        }

        List<String> userRoles = policyService.getCurrentRoles();
        String primaryRole = (userRoles != null && !userRoles.isEmpty()) ? userRoles.get(0) : "INVESTIGATOR";

        DocumentSignature signature = DocumentSignature.builder()
                .documentId(documentId)
                .versionId(targetVersionId)
                .signerId(currentUser.getId())
                .signerName(currentUser.getDisplayName() != null ? currentUser.getDisplayName() : currentUser.getKeycloakSubject())
                .signerRole(primaryRole)
                .signatureAlgorithm(sigAlgo)
                .signatureValue(finalSignature)
                .publicKeyCert(finalPublicKey)
                .documentHash(docHash)
                .signedAt(Instant.now())
                .verified(isValid)
                .build();

        signature = signatureRepository.save(signature);

        auditService.record("DOCUMENT_SIGNED", currentUser.getId(), documentId, document.getCaseId(),
                "DOCUMENT", Map.of(
                        "signatureId", signature.getId().toString(),
                        "versionId", targetVersionId.toString(),
                        "documentHash", docHash,
                        "algorithm", sigAlgo,
                        "verified", isValid
                ));

        log.info("Document {} version {} digitally signed by {} (signature ID: {})",
                documentId, targetVersionId, currentUser.getId(), signature.getId());

        return signature;
    }

    @Transactional(readOnly = true)
    public SignatureVerificationResult verifySignature(UUID signatureId) {
        DocumentSignature signature = signatureRepository.findById(signatureId)
                .orElseThrow(() -> new EntityNotFoundException("Signature not found: " + signatureId));

        Document document = documentRepository.findById(signature.getDocumentId())
                .orElseThrow(() -> new EntityNotFoundException("Document not found: " + signature.getDocumentId()));

        policyService.enforceCaseAccess(document.getCaseId());

        DocumentVersion version = documentVersionRepository.findById(signature.getVersionId())
                .orElseThrow(() -> new EntityNotFoundException("Document version not found: " + signature.getVersionId()));

        // Check if version hash matches signed hash
        boolean hashMatches = version.getContentHash().equalsIgnoreCase(signature.getDocumentHash());

        // Check cryptographic signature validity
        boolean cryptoValid = verifyCryptographicSignature(
                signature.getDocumentHash(),
                signature.getSignatureValue(),
                signature.getPublicKeyCert(),
                signature.getSignatureAlgorithm()
        );

        boolean fullyValid = hashMatches && cryptoValid && !signature.isRevoked();
        String verdict = fullyValid ? "VALID_SIGNATURE" :
                (!hashMatches ? "DOCUMENT_TAMPERED" :
                (!cryptoValid ? "INVALID_CRYPTOGRAPHIC_SIGNATURE" : "SIGNATURE_REVOKED"));

        return new SignatureVerificationResult(
                signature.getId(),
                signature.getDocumentId(),
                signature.getVersionId(),
                signature.getSignerName(),
                signature.getSignerRole(),
                signature.getSignatureAlgorithm(),
                signature.getSignedAt(),
                hashMatches,
                cryptoValid,
                signature.isRevoked(),
                fullyValid,
                verdict
        );
    }

    @Transactional(readOnly = true)
    public List<DocumentSignature> getSignaturesForDocument(UUID documentId) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found: " + documentId));
        policyService.enforceCaseAccess(document.getCaseId());
        return signatureRepository.findByDocumentIdOrderBySignedAtDesc(documentId);
    }

    private boolean verifyCryptographicSignature(String docHash, String signatureBase64, String publicKeyPem, String algorithm) {
        try {
            String cleanKey = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);

            Signature sig = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            sig.initVerify(publicKey);
            sig.update(docHash.getBytes(StandardCharsets.UTF_8));
            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            return sig.verify(sigBytes);
        } catch (Exception e) {
            log.warn("Cryptographic signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    public record SignatureVerificationResult(
            UUID signatureId,
            UUID documentId,
            UUID versionId,
            String signerName,
            String signerRole,
            String algorithm,
            Instant signedAt,
            boolean documentHashMatched,
            boolean cryptoVerified,
            boolean revoked,
            boolean isValid,
            String verdict
    ) {}
}
