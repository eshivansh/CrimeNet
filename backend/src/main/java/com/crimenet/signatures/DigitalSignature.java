package com.crimenet.signatures;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Cryptographic signing metadata for document versions (§3).
 * Immutable once created.
 */
@Entity
@Table(name = "digital_signature")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DigitalSignature extends BaseEntity {

    @Column(name = "document_version_id", nullable = false)
    private UUID documentVersionId;

    @Column(name = "signer_id", nullable = false)
    private UUID signerId;

    @Column(name = "signature_value", nullable = false, columnDefinition = "TEXT")
    private String signatureValue;

    @Column(name = "algorithm", nullable = false)
    @Builder.Default
    private String algorithm = "SHA256withRSA";

    @Column(name = "certificate_serial")
    private String certificateSerial;

    @Column(name = "signed_at", nullable = false)
    @Builder.Default
    private Instant signedAt = Instant.now();

    @Column(nullable = false)
    @Builder.Default
    private String status = "VALID"; // VALID | REVOKED
}
