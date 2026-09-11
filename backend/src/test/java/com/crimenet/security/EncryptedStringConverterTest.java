package com.crimenet.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Covers the PII column converter, which protects Aadhaar-class identifiers and the contact
 * details of victims and witnesses.
 */
class EncryptedStringConverterTest {

    private EncryptedStringConverter converter;

    @BeforeEach
    void setUp() {
        PiiEncryptionKeyProvider provider = new PiiEncryptionKeyProvider();
        ReflectionTestUtils.setField(provider, "configuredKey",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        ReflectionTestUtils.setField(provider, "configuredStrictMode", true);
        provider.initialise();

        converter = new EncryptedStringConverter();
    }

    @Test
    @DisplayName("values round-trip through encryption")
    void roundTrips() {
        String aadhaar = "4321 8765 0987";
        String stored = converter.convertToDatabaseColumn(aadhaar);

        assertThat(stored).startsWith("enc:v1:").doesNotContain(aadhaar);
        assertThat(converter.convertToEntityAttribute(stored)).isEqualTo(aadhaar);
    }

    @Test
    @DisplayName("the same plaintext encrypts differently every time")
    void usesAFreshNonceEachTime() {
        // GCM catastrophically loses confidentiality on nonce reuse, so this is the one
        // property of the construction that must never regress.
        String value = "+91 98200 11223";
        String first = converter.convertToDatabaseColumn(value);
        String second = converter.convertToDatabaseColumn(value);

        assertThat(first).isNotEqualTo(second);
        assertThat(converter.convertToEntityAttribute(first)).isEqualTo(value);
        assertThat(converter.convertToEntityAttribute(second)).isEqualTo(value);
    }

    @Test
    @DisplayName("tampered ciphertext is rejected rather than decrypted")
    void rejectsTamperedCiphertext() {
        String stored = converter.convertToDatabaseColumn("12 Nehru Marg, Lucknow");
        String tampered = stored.substring(0, stored.length() - 4)
                + (stored.endsWith("AAAA") ? "BBBB" : "AAAA");

        assertThatThrownBy(() -> converter.convertToEntityAttribute(tampered))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("plaintext in an encrypted column is refused in strict mode")
    void strictModeRejectsUnencryptedValues() {
        // Passing these through silently made a plaintext downgrade invisible and made it
        // impossible to assert that the column was encrypted at all.
        assertThatThrownBy(() -> converter.convertToEntityAttribute("4321 8765 0987"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unencrypted");
    }

    @Test
    @DisplayName("null and blank values pass through untouched")
    void passesThroughEmptyValues() {
        assertThat(converter.convertToDatabaseColumn(null)).isNull();
        assertThat(converter.convertToDatabaseColumn("")).isEmpty();
        assertThat(converter.convertToEntityAttribute(null)).isNull();
        assertThat(converter.convertToEntityAttribute("")).isEmpty();
    }

    @Test
    @DisplayName("startup fails when no encryption key is configured")
    void refusesToStartWithoutAKey() {
        // The key used to default to a literal committed to this repository.
        PiiEncryptionKeyProvider provider = new PiiEncryptionKeyProvider();
        ReflectionTestUtils.setField(provider, "configuredKey", "");

        assertThatThrownBy(provider::initialise)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("crimenet.security.encryption-key");
    }
}
