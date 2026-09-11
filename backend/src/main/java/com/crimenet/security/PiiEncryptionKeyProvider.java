package com.crimenet.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Resolves the master key used to encrypt PII columns.
 *
 * <p>Split out of {@link EncryptedStringConverter} for two reasons. First, the key had a
 * hardcoded default — twice — and the property was set in no configuration file, so that
 * literal was the effective key in every deployment and anyone with the repository could
 * decrypt the identity data of victims and witnesses. There is no default here: the
 * application refuses to start without a configured key.
 *
 * <p>Second, Hibernate instantiates an {@code AttributeConverter} itself through its no-arg
 * constructor, while Spring instantiates the same class as a bean. Both wrote a shared,
 * non-volatile {@code static} field, so whichever ran last won — meaning the no-arg
 * fallback could silently install the default key even when a real one was configured, and
 * rows written under one key became undecryptable under the other. The key now lives in
 * one place, is published through a volatile field, and has exactly one writer.
 */
@Slf4j
@Component
public class PiiEncryptionKeyProvider {

    private static volatile SecretKey key;
    private static volatile boolean strictMode = true;

    @Value("${crimenet.security.encryption-key:}")
    private String configuredKey;

    /**
     * When true, a column value without the {@code enc:v1:} prefix is rejected on read
     * rather than passed through as plaintext. Turn it off only while backfilling.
     */
    @Value("${crimenet.security.encryption-strict:true}")
    private boolean configuredStrictMode;

    @PostConstruct
    void initialise() {
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new IllegalStateException("""
                    crimenet.security.encryption-key is not set.

                    This key protects id_number_encrypted, contact_encrypted and \
                    address_encrypted — the identity and contact details of victims, \
                    witnesses and suspects. It previously defaulted to a literal committed \
                    to this repository, which meant the data was not meaningfully encrypted \
                    at all. There is deliberately no default any more.

                    Set CRIMENET_ENCRYPTION_KEY to a 32-byte key, ideally sourced from a KMS \
                    or vault. For local development the demo launcher generates one.""");
        }

        key = deriveKey(configuredKey);
        strictMode = configuredStrictMode;
        log.info("PII encryption key initialised ({}), strict mode: {}",
                describeSource(configuredKey), strictMode);
    }

    /**
     * Initialises the key outside a Spring context, for command-line tools such as
     * {@code DemoDocumentVerificationSuite} that exercise the converter directly.
     *
     * <p>Refuses to run once a key is set, so it cannot be used to swap the key out from
     * under a running application.
     */
    public static synchronized void initialiseStandalone(String keyMaterial, boolean strict) {
        if (key != null) {
            throw new IllegalStateException(
                    "The PII encryption key is already initialised and cannot be replaced.");
        }
        PiiEncryptionKeyProvider provider = new PiiEncryptionKeyProvider();
        provider.configuredKey = keyMaterial;
        provider.configuredStrictMode = strict;
        provider.initialise();
    }

    static SecretKey key() {
        SecretKey resolved = key;
        if (resolved == null) {
            throw new IllegalStateException(
                    "PII encryption key has not been initialised. This means an entity was "
                            + "loaded before the Spring context started, which should not happen.");
        }
        return resolved;
    }

    static boolean strict() {
        return strictMode;
    }

    /**
     * Accepts a raw 256-bit key as base64 or hex — the form a KMS hands back — and falls
     * back to hashing a passphrase for local use. A passphrase is not a key: a single
     * unsalted SHA-256 has no work factor, so brute-forcing it costs whatever guessing the
     * passphrase costs.
     */
    private SecretKey deriveKey(String configured) {
        String trimmed = configured.trim();

        if (trimmed.length() == 64 && trimmed.matches("(?i)[0-9a-f]{64}")) {
            return new SecretKeySpec(HexFormat.of().parseHex(trimmed), "AES");
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            if (decoded.length == 32) {
                return new SecretKeySpec(decoded, "AES");
            }
        } catch (IllegalArgumentException ignored) {
            // Not base64; treat it as a passphrase below.
        }

        log.warn("crimenet.security.encryption-key is not a 256-bit key in hex or base64. "
                + "Deriving one by SHA-256 over the passphrase — acceptable for local development, "
                + "not for anything holding real case data.");
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return new SecretKeySpec(sha256.digest(trimmed.getBytes(StandardCharsets.UTF_8)), "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialise the PII encryption key", e);
        }
    }

    private String describeSource(String configured) {
        String trimmed = configured.trim();
        if (trimmed.length() == 64 && trimmed.matches("(?i)[0-9a-f]{64}")) {
            return "256-bit hex key";
        }
        try {
            if (Base64.getDecoder().decode(trimmed).length == 32) {
                return "256-bit base64 key";
            }
        } catch (IllegalArgumentException ignored) {
            // fall through
        }
        return "passphrase-derived key";
    }
}
