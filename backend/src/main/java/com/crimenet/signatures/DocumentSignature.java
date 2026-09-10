package com.crimenet.signatures;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "document_signature")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentSignature extends BaseEntity {

    @Column(name = "document_id", nullable = false)
    private UUID documentId;

    @Column(name = "version_id")
    private UUID versionId;

    @Column(name = "signer_id", nullable = false)
    private UUID signerId;

    @Column(name = "signer_name", nullable = false)
    private String signerName;

    @Column(name = "signer_role", nullable = false)
    private String signerRole;

    @Column(name = "signature_algorithm", nullable = false)
    @Builder.Default
    private String signatureAlgorithm = "SHA256withRSA";

    @Column(name = "signature_value", nullable = false, columnDefinition = "TEXT")
    private String signatureValue;

    @Column(name = "public_key_cert", nullable = false, columnDefinition = "TEXT")
    private String publicKeyCert;

    @Column(name = "document_hash", nullable = false)
    private String documentHash;

    @Column(name = "signed_at", nullable = false)
    @Builder.Default
    private Instant signedAt = Instant.now();

    @Column(nullable = false)
    @Builder.Default
    private boolean verified = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;
}
