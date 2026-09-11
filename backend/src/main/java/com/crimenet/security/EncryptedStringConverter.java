package com.crimenet.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JPA AttributeConverter that encrypts and decrypts sensitive PII columns using AES-256-GCM.
 * Protects id_number_encrypted, contact_encrypted, and address_encrypted at rest.
 */
@Slf4j
@Component
@Converter(autoApply = false)
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final String ENCRYPTED_PREFIX = "enc:v1:";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Hibernate constructs this converter itself, so it cannot take the key as a
     * constructor argument. The key is resolved once by {@link PiiEncryptionKeyProvider}
     * and read from there — no hardcoded default, and no second writer.
     */
    public EncryptedStringConverter() {
        // Intentionally empty.
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.isBlank()) {
            return attribute;
        }

        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.ENCRYPT_MODE, PiiEncryptionKeyProvider.key(), parameterSpec);

            byte[] cipherText = cipher.doFinal(attribute.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);

            return ENCRYPTED_PREFIX + Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            log.error("Failed to encrypt sensitive PII column: {}", e.getMessage());
            throw new RuntimeException("PII column encryption failed", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) {
            return dbData;
        }

        if (!dbData.startsWith(ENCRYPTED_PREFIX)) {
            // An unprefixed value is plaintext PII sitting in a column that is supposed to
            // be encrypted. Passing it through silently made a plaintext downgrade attack
            // invisible and made it impossible to assert that these columns are encrypted
            // at all. Strict mode is relaxed only while backfilling legacy rows.
            if (PiiEncryptionKeyProvider.strict()) {
                throw new IllegalStateException(
                        "Encountered an unencrypted value in a PII column. Backfill the legacy "
                                + "rows and re-encrypt them, or set crimenet.security.encryption-strict=false "
                                + "for the duration of the migration.");
            }
            log.warn("PII_PLAINTEXT_COLUMN: reading an unencrypted value from an encrypted column");
            return dbData;
        }

        try {
            String rawBase64 = dbData.substring(ENCRYPTED_PREFIX.length());
            byte[] cipherMessage = Base64.getDecoder().decode(rawBase64);

            ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, PiiEncryptionKeyProvider.key(), parameterSpec);

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to decrypt sensitive PII column: {}", e.getMessage());
            throw new RuntimeException("PII column decryption failed", e);
        }
    }
}
