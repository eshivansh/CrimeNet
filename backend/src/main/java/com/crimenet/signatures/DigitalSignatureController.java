package com.crimenet.signatures;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/documents/{documentId}/signatures")
@RequiredArgsConstructor
@Tag(name = "Digital Signatures", description = "Cryptographic digital signature lifecycle and verification")
public class DigitalSignatureController {

    private final DigitalSignatureService digitalSignatureService;

    @PostMapping
    @PreAuthorize("hasAnyRole('INVESTIGATOR', 'SUPERVISOR', 'FORENSIC_OFFICER', 'ADMIN')")
    @Operation(summary = "Digitally sign a document or document version")
    public ResponseEntity<DocumentSignature> signDocument(
            @PathVariable UUID documentId,
            @Valid @RequestBody(required = false) SignDocumentRequest request) {

        UUID versionId = request != null ? request.versionId() : null;
        String signature = request != null ? request.signatureBase64() : null;
        String publicKey = request != null ? request.publicKeyPem() : null;
        String algorithm = request != null ? request.algorithm() : "SHA256withRSA";

        DocumentSignature docSig = digitalSignatureService.signDocument(
                documentId, versionId, signature, publicKey, algorithm);
        return ResponseEntity.status(HttpStatus.CREATED).body(docSig);
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "List all digital signatures attached to a document")
    public ResponseEntity<List<DocumentSignature>> getSignatures(@PathVariable UUID documentId) {
        return ResponseEntity.ok(digitalSignatureService.getSignaturesForDocument(documentId));
    }

    @GetMapping("/{signatureId}/verify")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Cryptographically verify a specific document signature")
    public ResponseEntity<DigitalSignatureService.SignatureVerificationResult> verifySignature(
            @PathVariable UUID documentId,
            @PathVariable UUID signatureId) {
        return ResponseEntity.ok(digitalSignatureService.verifySignature(signatureId));
    }

    public record SignDocumentRequest(
            UUID versionId,
            String signatureBase64,
            String publicKeyPem,
            String algorithm
    ) {}
}
